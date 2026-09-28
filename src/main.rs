use std::process::ExitCode;

use clap::Parser;
use embedded_debugger::{
    cli::{
        Cli, execute, serve_flash_session_stdio, serve_mcp_stdio, serve_session_stdio,
        serve_supervisor_mcp,
    },
    envelope::{ErrorEnvelope, SuccessEnvelope},
};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let operation = cli.operation_name();
    if cli.is_flash_session_server() {
        return match serve_flash_session_stdio(&cli) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!(
                    "{}",
                    serde_json::to_string(&ErrorEnvelope::new(operation, &error))
                        .expect("flash session error envelope serializes")
                );
                ExitCode::from(u8::try_from(error.exit_code).unwrap_or(10))
            }
        };
    }
    if cli.is_session_server() {
        return match serve_session_stdio(&cli) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let envelope = ErrorEnvelope::new(operation, &error);
                eprintln!(
                    "{}",
                    serde_json::to_string(&envelope)
                        .expect("session startup error envelope always serializes")
                );
                ExitCode::from(u8::try_from(error.exit_code).unwrap_or(10))
            }
        };
    }
    if cli.is_mcp_server() {
        return match serve_mcp_stdio(&cli) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let envelope = ErrorEnvelope::new(operation, &error);
                eprintln!(
                    "{}",
                    serde_json::to_string(&envelope)
                        .expect("MCP startup error envelope always serializes")
                );
                ExitCode::from(u8::try_from(error.exit_code).unwrap_or(10))
            }
        };
    }
    if cli.is_supervisor_server() {
        return match serve_supervisor_mcp(&cli) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let envelope = ErrorEnvelope::new(operation, &error);
                eprintln!(
                    "{}",
                    serde_json::to_string(&envelope)
                        .expect("supervisor startup error envelope always serializes")
                );
                ExitCode::from(u8::try_from(error.exit_code).unwrap_or(10))
            }
        };
    }
    match execute(&cli) {
        Ok(result) => {
            if cli.json {
                let envelope = SuccessEnvelope::new(result.operation, result.data);
                println!(
                    "{}",
                    serde_json::to_string(&envelope).expect("success envelope always serializes")
                );
            } else {
                println!("{}", result.human);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            if cli.json {
                let envelope = ErrorEnvelope::new(operation, &error);
                println!(
                    "{}",
                    serde_json::to_string(&envelope).expect("error envelope always serializes")
                );
            } else {
                eprintln!("[{}] {}", serde_error_code(error.code), error.message);
                for action in &error.suggested_actions {
                    eprintln!("Suggested action: {}", action.action);
                }
            }
            ExitCode::from(u8::try_from(error.exit_code).unwrap_or(10))
        }
    }
}

fn serde_error_code(code: embedded_debugger::error::ErrorCode) -> String {
    serde_json::to_value(code)
        .expect("error code always serializes")
        .as_str()
        .expect("error code serializes as a string")
        .to_string()
}
