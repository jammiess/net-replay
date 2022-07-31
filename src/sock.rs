//! Create a raw socket
//!
//! Only supports creating a raw socket for reading TCP packets.

use libc::{
    self, __errno_location, c_int, close, recvfrom, socket, AF_INET, EACCES, EFAULT, EINVAL,
    EMSGSIZE, EAGAIN, EOPNOTSUPP, EPERM, EPROTO, IPPROTO_TCP, SOCK_RAW, SOCK_NONBLOCK,
};
use thiserror::Error;

use std::convert::From;
use std::io::Read;
use std::io::Result as IOResult;
use std::io::{Error, ErrorKind};
use std::time::{Duration, Instant};

/// Errors that can be generated when working with a raw socket
///
/// These error types are just pulled from libc. You should read the man pages about raw sockets and socket functions
/// to fully understand all of the errors and everything that can go wrong.
#[derive(Error, Debug)]
pub enum RSockErr {
    #[error("Tried to send broadcast address without broadcast flag")]
    Eaccess,
    #[error("Invalid memory address supplied")]
    Efault,
    #[error("Invalid argument passed")]
    Einval,
    #[error("Packet too large")]
    Emsgsize,
    #[error("Invalid flag passed to socket call")]
    Eopnotsupp,
    #[error("User doesn't have permissions for operation")]
    Eperm,
    #[error("ICMP error")]
    Eproto,
    #[error("Try operation again")]
    Eagain,
    #[error("Got errno {0}")]
    Errno(isize),
}

impl From<c_int> for RSockErr {
    fn from(val: c_int) -> Self {
        match val {
            EACCES => Self::Eaccess,
            EFAULT => Self::Efault,
            EINVAL => Self::Einval,
            EMSGSIZE => Self::Emsgsize,
            EOPNOTSUPP => Self::Eopnotsupp,
            EPERM => Self::Eperm,
            EPROTO => Self::Eproto,
            EAGAIN => Self::Eagain,
            x => Self::Errno(x as isize),
        }
    }
}

#[derive(Debug, Error)]
pub enum TimeoutRead {
    /// Error occurred while trying to read
    #[error("Failed to read from socket")]
    IO(#[from] RSockErr),
    /// Read timed out
    #[error("No bytes were returned before timeout")]
    Timeout,
}

/// A linux raw socket
///
/// You should really read through the linux man pages about sockets and raw sockets before using this library.
/// Raw sockets have non-standard behavior when compared to UDP or TCP sockets. A raw socket will be able to read
/// all of the packets on an interface or machine and it is up to the user to filter those packets.
pub struct Raw(c_int);

impl Raw {
    /// Create a new raw socket
    ///
    /// This socket can be used to read raw ip packets from a machine's interface. The socket will have the
    /// non-blocking flag set.
    ///
    /// # Errors
    /// Creating a raw socket will require elevated privileges or capabilities. Any program that uses this struct
    /// should be run as root or with the net raw capability.
    ///
    /// If the program has insufficient privileges, then [`RSockErr::Eperm`] will be returned.
    pub fn new() -> Result<Self, RSockErr> {
        // SAFETY: This is a completely standard syscall. All of these types and values are exported by
        // libc. If the call fails, then no socket will be returned so you can't accidentally access
        // some other file descriptor.
        let fd = unsafe { socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_TCP) };
        if fd < 0 {
            // SAFETY: libc should ensure that the pointer is aligned properly. A syscall has been made so the
            // errno value should be initialized to a valid value.
            let errno = unsafe { *__errno_location() };
            Err(errno.into())
        } else {
            Ok(Raw(fd))
        }
    }

    /// Bind socket to a specific interface
    ///
    /// Binds a raw socket to a specific network interface. Once it is bound, only packets seen on that interface will
    /// get read by this socket.
    ///
    /// # Errors
    /// This can throw an error if the name of the interface does not match the names of any network interfaces.
    /// You can see valid interfaces by running a command like `ip a`.
    pub fn bind_interface(&mut self, interface: &dyn AsRef<str>) -> Result<(), RSockErr> {
        let interface = interface.as_ref();
        if interface.len() > libc::IFNAMSIZ {
            return Err(RSockErr::Einval);
        }
        let iface = interface.as_ptr();
        // SAFETY: Just a normal C function call. The linux kernel / libc should check all of the arguments. However,
        // all of the arguments should be valid. The only way to get the socket fd is from new which checks to ensure
        // the socket call succeeded. SOL_SOCKET and SO_BINDTODEVICE are both exported from libc and so are valid.
        // Interface being a valid safe &str means it will be properly aligned and initialized.
        let ret = unsafe {
            libc::setsockopt(
                self.0,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                iface.cast(),
                interface.len() as u32,
            )
        };
        if ret < 0 {
            // SAFETY: libc should ensure that the pointer is aligned properly. A syscall has been made so the
            // errno value should be initialized to a valid value.
            let errno = unsafe { *__errno_location() };
            return Err(errno.into());
        }
        Ok(())
    }

    /// Try to read from a socket with a timeout
    ///
    /// If a socket is non-blocking, this method will attempt to read from that socket for a specified amount of time
    /// before returning with an error or data. This method will immediately return once any amount of data even if
    /// the buffer is not full and there is still time left before timing out. This read will also return immediately
    /// if an error other than [`EAGAIN`] is returned from an attempted read.
    ///
    /// If the socket is not non-blocking, this will act as a normal read.
    ///
    /// # Errors
    /// Can return any error that [`Raw::read`] can return. Or it will return the timeout error that indicates no data
    /// was read before the operation timed out.
    pub fn read_timeout(&mut self, buf: &mut [u8], timeout: &Duration) -> Result<usize, TimeoutRead> {
        let start = Instant::now();
        'try_loop: loop {
            let read = self.read(buf);
            match read {
                Ok(n) => return Ok(n),
                Err(e) => {
                    // SAFETY: This should always work. The error is returned from [`Raw::read`] which will only return
                    // errors that were created with [`std::io::Error::new`]. That means there will always be an inner
                    // value that can be returned.
                    let inner = unsafe { e.into_inner().unwrap_unchecked() };
                    // SAFETY: Like above, the inner error type is always of the [`RSockErr`] type which means this
                    // operation will never fail.
                    let sock_err = unsafe { inner.downcast::<RSockErr>().unwrap_unchecked() };
                    match *sock_err {
                        RSockErr::Eagain => {},
                        e => return Err(TimeoutRead::IO(e)),
                    };
                }
            };
            let elapsed = start.elapsed();
            if elapsed > *timeout {
                break 'try_loop;
            }
        }
        Err(TimeoutRead::Timeout)
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        unsafe {
            close(self.0);
        }
    }
}

impl Read for Raw {
    fn read(&mut self, buf: &mut [u8]) -> IOResult<usize> {
        let addr = buf.as_mut_ptr();
        // SAFETY: This function has a mutable reference to the buffer so no other thread or process can mutate
        // it while data is being read into it. Additionally, the buffer comes from safe code so it should be
        // properly aligned. It's valid to pass NULL as a parameter for the last two values so there are no
        // invalid parameters.
        let ret = unsafe { recvfrom(self.0, addr.cast(), buf.len(), 0, 0 as _, 0 as _) };
        if ret > 0 {
            Ok(ret as usize)
        } else {
            // SAFETY: libc should ensure that the pointer is aligned properly. A syscall has been made so the
            // errno value should be initialized to a valid value.
            let errno = unsafe { *__errno_location() };
            let err: RSockErr = errno.into();
            Err(Error::new(ErrorKind::Other, err))
        }
    }
}
