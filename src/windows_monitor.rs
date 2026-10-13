//! Bounded Windows monitor cleanup using job accounting, not consumed exit packets.

use std::{
    io::{self, Error},
    mem::{size_of, zeroed},
    os::windows::{io::AsRawHandle, process::CommandExt},
    process::{Child, Command, ExitStatus},
    ptr::{null, null_mut},
    thread,
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
        },
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
            QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
        },
        Threading::{
            CREATE_NO_WINDOW, CREATE_SUSPENDED, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
        },
    },
};

#[derive(Debug)]
struct Job(HANDLE);

impl Job {
    fn new() -> io::Result<Self> {
        let handle = unsafe { CreateJobObjectW(null(), null()) };
        if handle.is_null() {
            return Err(Error::last_os_error());
        }
        let job = Self(handle);
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(Error::last_os_error());
        }
        Ok(job)
    }

    fn active(&self) -> io::Result<u32> {
        let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
        if unsafe {
            QueryInformationJobObject(
                self.0,
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                null_mut(),
            )
        } == 0
        {
            return Err(Error::last_os_error());
        }
        Ok(accounting.ActiveProcesses)
    }

    fn kill(&self) -> io::Result<()> {
        if unsafe { TerminateJobObject(self.0, 1) } == 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn resume_primary(pid: u32) -> io::Result<()> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(Error::last_os_error());
    }
    let result = (|| {
        let mut entry: THREADENTRY32 = unsafe { zeroed() };
        entry.dwSize = size_of::<THREADENTRY32>() as u32;
        let mut present = unsafe { Thread32First(snapshot, &mut entry) };
        let mut primary = None;
        while present != 0 {
            if entry.th32OwnerProcessID == pid && primary.replace(entry.th32ThreadID).is_some() {
                return Err(Error::other("suspended monitor has multiple threads"));
            }
            entry.dwSize = size_of::<THREADENTRY32>() as u32;
            present = unsafe { Thread32Next(snapshot, &mut entry) };
        }
        let primary = primary.ok_or_else(|| Error::other("monitor primary thread missing"))?;
        let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, primary) };
        if thread.is_null() {
            return Err(Error::last_os_error());
        }
        let count = unsafe { ResumeThread(thread) };
        unsafe { CloseHandle(thread) };
        if count != 1 {
            return Err(Error::other(
                "monitor resume did not observe one suspend count",
            ));
        }
        Ok(())
    })();
    unsafe { CloseHandle(snapshot) };
    result
}

pub(crate) struct MonitorChild {
    child: Child,
    job: Job,
}

impl MonitorChild {
    pub(crate) fn spawn(mut command: Command) -> io::Result<Self> {
        let job = Job::new()?;
        let mut child = command
            .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW)
            .spawn()?;
        let assigned = unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle()) };
        if assigned == 0 {
            let error = Error::last_os_error();
            let _ = child.kill();
            let _ = child.wait(); // The child never executed or spawned descendants.
            return Err(error);
        }
        let mut managed = Self { child, job };
        if let Err(error) = resume_primary(managed.child.id()) {
            let _ = managed.start_kill();
            let _ = managed.wait();
            return Err(error);
        }
        Ok(managed)
    }

    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        // Root exit alone does not prove that descendants have stopped.
        if status.is_some() && self.job.active()? == 0 {
            Ok(status)
        } else {
            Ok(None)
        }
    }

    pub(crate) fn start_kill(&mut self) -> io::Result<()> {
        self.job.kill()
    }

    pub(crate) fn wait(&mut self) -> io::Result<ExitStatus> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(Error::new(
                    io::ErrorKind::TimedOut,
                    "monitor job did not exit",
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for MonitorChild {
    fn drop(&mut self) {
        let _ = self.start_kill();
        let _ = self.wait();
        // Closing the last job handle also terminates any surviving descendants.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    #[test]
    fn polled_monitor_can_be_waited_again_without_exit_notification() {
        let mut command = Command::new("cmd.exe");
        command
            .args(["/d", "/c", "exit", "0"])
            .stdout(Stdio::null());
        let mut child = MonitorChild::spawn(command).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(20));
        }
        assert!(child.wait().unwrap().success());
        assert!(child.wait().unwrap().success());
        assert_eq!(child.job.active().unwrap(), 0);
    }

    #[test]
    #[allow(clippy::zombie_processes)] // Intentional orphan: the enclosing test Job must reap it.
    fn descendant_helper() {
        let Some(marker) = std::env::var_os("ED_MONITOR_TEST_MARKER") else {
            return;
        };
        Command::new("cmd.exe")
            .args(["/d", "/c", "ping -n 60 127.0.0.1 >nul"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        std::fs::write(marker, b"descendant started").unwrap();
    }

    #[test]
    fn root_exit_does_not_hide_live_descendants() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("started");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "windows_monitor::tests::descendant_helper",
                "--exact",
                "--nocapture",
            ])
            .env("ED_MONITOR_TEST_MARKER", &marker)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = MonitorChild::spawn(command).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !marker.exists() || child.child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(20));
        }
        assert!(child.try_wait().unwrap().is_none());
        assert!(child.job.active().unwrap() > 0);
        child.start_kill().unwrap();
        let _ = child.wait().unwrap();
        assert_eq!(child.job.active().unwrap(), 0);
    }
}
