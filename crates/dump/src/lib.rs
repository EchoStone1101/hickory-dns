use std::sync::Arc;

pub trait Walk {
    fn walk(&self);
}

pub trait Dump {
    fn dump(&self);
}

#[macro_export]
macro_rules! dump(
    ($($ty:ty),+) => (
        $(
            impl $crate::Dump for $ty {
                #[inline(always)]
                fn dump(&self) {
                    unsafe {
                        let some_bytes: &[u8] = std::slice::from_raw_parts(
                            self as *const $ty as *const u8,
                            std::mem::size_of::<$ty>(),
                        );
                        println!("{:p} memory layout: {:x?}", self, some_bytes);
                    }
                    // println!("{:p}: {}", self, *self);
                }
            }
        )+
    );
);

dump!(u8, u16, u32, u64, usize, bool);
dump!(i8, i16, i32, i64, isize);

impl<T: Dump> Dump for [T] {
    fn dump(&self) {
        unsafe {
            let some_bytes: &[u8] = std::slice::from_raw_parts(
                self as *const [T] as *const u8,
                std::mem::size_of::<T>() * self.len(),
            );
            println!("{:p} memory layout: {:x?}", self, some_bytes);
        }
    }
}

impl<T> Dump for Option<T> {
    fn dump(&self) {
        unsafe {
            let some_bytes: &[u8] = std::slice::from_raw_parts(
                self as *const Option<T> as *const u8,
                std::mem::size_of::<Option<T>>(),
            );
            println!("{:p} memory layout: {:x?}", self, some_bytes);
        }
    }
} 

#[macro_export]
macro_rules! walk_default(
    ($($ty:ty),+) => (
        $(
            impl $crate::Walk for $ty {
                #[inline(always)]
                fn walk(&self) {}
            }
        )+
    );
);

walk_default!(u8, u16, u32, u64, usize, bool);
walk_default!(i8, i16, i32, i64, isize);

impl<T: Walk> Walk for Option<T> {
    fn walk(&self) {
        if let Some(s) = self {
            s.walk();
        }
    }
}

impl<T: Walk + Dump> Walk for Box<T> {
    fn walk(&self) {
        (&**self).dump();
        (&**self).walk();
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
    fn dump(&self) {
        unsafe {
            let some_bytes: &[u8] = std::slice::from_raw_parts(
                self as *const ArcInner<T> as *const u8,
                std::mem::size_of::<ArcInner<T>>(),
            );
            println!("{:p} memory len={}, layout: {:x?}", self, std::mem::size_of::<ArcInner<T>>(), some_bytes);
        }
        // println!("{:p}: {}", self, *self);
    }
}

impl<T: Walk> Walk for Arc<T> {
    fn walk(&self) {
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
            inner.dump();
        }

        (&**self).walk();
    }
}

impl<T: Walk> Walk for [T] {
    fn walk(&self) {
        for e in self.iter() {
            e.walk();
        }
    }
} 

impl<T: Walk> Walk for Vec<T> {
    fn walk(&self) {
        if !self.is_empty() {
            unsafe {
                let some_bytes: &[u8] = std::slice::from_raw_parts(
                    &**self as *const [T] as *const u8,
                    std::mem::size_of::<T>() * self.len(),
                );
                println!("{:p} memory layout: {:x?}", &**self, some_bytes);
            }
        }

        for e in self.iter() {
            e.walk();
        }
    }
}
