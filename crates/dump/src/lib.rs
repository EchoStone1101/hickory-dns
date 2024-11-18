use std::net::SocketAddr;
use std::sync::Arc;
use std::io::Write;

pub trait Walk {
    fn walk(&self, f: &mut Vec<u8>);
}

pub trait Dump {
    fn dump(&self, f: &mut Vec<u8>);
}

#[macro_export]
macro_rules! dump(
    ($($ty:ty),+) => (
        $(
            impl $crate::Dump for $ty {
                #[inline(always)]
                fn dump(&self, f: &mut Vec<u8>) {
                    use std::io::Write;
                    let size = std::mem::size_of::<$ty>();
                    unsafe {
                        let some_bytes: &[u8] = std::slice::from_raw_parts(
                            self as *const $ty as *const u8,
                            size,
                        );
                        _ = write!(f, "\"{:p}\": {{ \"data\": {:?}, \"__size__\": {}, \"__type__\": \"unknown\" }}, ", self, some_bytes, size);
                    }
                }
            }
        )+
    );
);

#[macro_export]
macro_rules! dump_with_type(
    ($ty:ty, $name:expr) => (
        impl $crate::Dump for $ty {
            #[inline(always)]
            fn dump(&self, f: &mut Vec<u8>) {
                use std::io::Write;
                let size = std::mem::size_of::<$ty>();
                unsafe {
                    let some_bytes: &[u8] = std::slice::from_raw_parts(
                        self as *const $ty as *const u8,
                        size,
                    );
                    _ = write!(f, "\"{:p}\": {{ \"data\": {:?}, \"__size__\": {}, \"__type__\": \"{}\" }}, ", self, some_bytes, size, $name);
                }
            }
        }
    );
);

dump!(u8, u16, u32, u64, usize, bool);
dump!(i8, i16, i32, i64, isize);

impl<T: Dump> Dump for [T] {
    fn dump(&self, f: &mut Vec<u8>) {
        let size = std::mem::size_of::<T>();
        unsafe {
            let some_bytes: &[u8] = std::slice::from_raw_parts(
                self as *const [T] as *const u8,
                size * self.len(),
            );
            _ = write!(f, "\"{:p}\": {{ \"data\": {:?}, \"__size__\": {}, \"__length__\": {}, \"__type__\": \"array unknown\" }}, ", self, some_bytes, size, self.len());
        }
    }
}

impl<T> Dump for Option<T> {
    fn dump(&self, f: &mut Vec<u8>) {
        let size = std::mem::size_of::<Option<T>>();
        unsafe {
            let some_bytes: &[u8] = std::slice::from_raw_parts(
                self as *const Option<T> as *const u8,
                size,
            );
            _ = write!(f, "\"{:p}\": {{ \"data\": {:?}, \"__size__\": {}, \"__type__\": \"option unknown\" }}, ", self, some_bytes, size);
        }
    }
} 

#[macro_export]
macro_rules! walk_default(
    ($($ty:ty),+) => (
        $(
            impl $crate::Walk for $ty {
                #[inline(always)]
                fn walk(&self, _f: &mut Vec<u8>) {}
            }
        )+
    );
);

walk_default!(u8, u16, u32, u64, usize, bool);
walk_default!(i8, i16, i32, i64, isize, SocketAddr);

impl<T: Walk> Walk for Option<T> {
    fn walk(&self, f: &mut Vec<u8>) {
        if let Some(s) = self {
            s.walk(f);
        }
    }
}

impl<T: Walk + Dump> Walk for Box<T> {
    fn walk(&self, f: &mut Vec<u8>) {
        (&**self).dump(f);
        (&**self).walk(f);
    }
}

#[repr(C)]
struct ArcInner<T: ?Sized> {
    strong: std::sync::atomic::AtomicUsize,
    weak: std::sync::atomic::AtomicUsize,
    data: T,
}

impl<T> Dump for ArcInner<T> {
    #[inline(always)]
    fn dump(&self, f: &mut Vec<u8>) {
        let size = std::mem::size_of::<ArcInner<T>>();
        let ty = match size {
            136 => "%\\\"alloc::sync::ArcInner<hickory_proto::rr::rr_set::RecordSet>\\\"",
            152 => "%\\\"alloc::sync::ArcInner<hickory_server::store::file::authority::FileAuthority>\\\"",
            _ => "unknown"
        };
        unsafe {
            let some_bytes: &[u8] = std::slice::from_raw_parts(
                self as *const ArcInner<T> as *const u8,
                size,
            );

            let mut some_bytes = some_bytes.to_vec();

            if some_bytes[0] == 1 {
                some_bytes[0] = 2;
            }

            if some_bytes[8] == 1 {
                some_bytes[8] = 2;
            }

            let some_bytes: &[u8] = &some_bytes;

            _ = write!(f, "\"{:p}\": {{ \"data\": {:?}, \"__size__\": {}, \"__type__\": \"{}\" }}, ", self, some_bytes, size, ty);
        }
    }
}

impl<T: Walk> Walk for Arc<T> {
    fn walk(&self, f: &mut Vec<u8>) {
        let inner_ptr_u64 = unsafe {
            let some_bytes: &[u8] = std::slice::from_raw_parts(
                self as *const Arc<T> as *const u8,
                std::mem::size_of::<Arc<T>>(),
            );

            u64::from_le_bytes(some_bytes[0..8].try_into().unwrap())
        };

        let inner_ptr = inner_ptr_u64 as *const ArcInner<T>;

        unsafe {
            let inner = &*inner_ptr;
            inner.dump(f);
        }

        (&**self).walk(f);
    }
}

impl<T: Walk> Walk for [T] {
    fn walk(&self, f: &mut Vec<u8>) {
        for e in self.iter() {
            e.walk(f);
        }
    }
} 

impl<T: Walk> Walk for Vec<T> {
    fn walk(&self, f: &mut Vec<u8>) {
        if !self.is_empty() {
            let size = std::mem::size_of::<T>();
    
            unsafe {
                let some_bytes: &[u8] = std::slice::from_raw_parts(
                    &**self as *const [T] as *const u8,
                    size * self.len(),
                );

                let ty = match size {
                    216 => match some_bytes[0] {
                        0 => "RecordAa",
                        1 => "RecordAaaa",
                        2 | 4 | 11 => "RecordName",
                        8 => "RecordMx",
                        15 => "RecordSoa",
                        20 => "RecordTxt",
                        _ => unreachable!("unknown type {}", some_bytes[0])
                    }, 
                    1 => "i8",
                    _ => "unknown"
                };
    
                _ = write!(f, "\"{:p}\": {{ \"data\": {:?}, \"__size__\": {}, \"__length__\": {}, \"__type__\": \"{}\" }}, ", &**self, some_bytes, size, self.len(), ty);
            }
        }

        for e in self.iter() {
            e.walk(f);
        }
    }
}
