//! Pure producer-side reservation, shared with host tests. Reserve one empty byte.
#[derive(Debug, PartialEq, Eq)]
pub struct Reservation {
    pub first: usize,
    pub second: usize,
    pub next_write: usize,
}

pub fn reserve(size: usize, write: usize, read: usize, bytes: usize) -> Option<Reservation> {
    if size < 2 || write >= size || read >= size || bytes >= size {
        return None;
    }
    let free = if read > write {
        read - write - 1
    } else {
        size - write + read - 1
    };
    if bytes > free {
        return None;
    }
    let first = bytes.min(size - write);
    Some(Reservation {
        first,
        second: bytes - first,
        next_write: (write + bytes) % size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_without_overwriting_unread_bytes() {
        assert_eq!(
            reserve(16, 14, 8, 6),
            Some(Reservation {
                first: 2,
                second: 4,
                next_write: 4
            })
        );
        assert!(reserve(16, 14, 4, 6).is_none());
    }

    #[test]
    fn full_empty_and_invalid_cursors() {
        assert!(reserve(8, 7, 0, 1).is_none());
        assert_eq!(reserve(8, 0, 0, 7).unwrap().next_write, 7);
        assert!(reserve(8, 0, 0, 8).is_none());
        assert!(reserve(8, 8, 0, 1).is_none());
        assert!(reserve(1, 0, 0, 0).is_none());
    }

    #[test]
    fn exhaustive_small_rings_keep_every_unread_slot() {
        for size in 2..32 {
            for write in 0..size {
                for read in 0..size {
                    let used = (write + size - read) % size;
                    for bytes in 0..=size {
                        let result = reserve(size, write, read, bytes);
                        assert_eq!(result.is_some(), bytes < size - used);
                        if let Some(result) = result {
                            assert_eq!(result.first + result.second, bytes);
                            assert_eq!(result.next_write, (write + bytes) % size);
                        }
                    }
                }
            }
        }
    }
}
