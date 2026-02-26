use std::ffi::CString;
use std::mem;
use std::os::raw::{c_char, c_void};

use block2::Block;
use objc2::encode::{Encode, Encoding, RefEncode};

#[repr(C)]
pub struct dispatch_object_s {
    _private: [u8; 0],
}

unsafe impl Encode for dispatch_object_s {
    const ENCODING: Encoding = Encoding::Object;
}

unsafe impl RefEncode for dispatch_object_s {
    const ENCODING_REF: Encoding = Encoding::Object;
}

#[allow(non_camel_case_types)]
pub type dispatch_function_t = extern "C" fn(*mut c_void);
#[allow(non_camel_case_types)]
pub type dispatch_object_t = *mut dispatch_object_s;
#[allow(non_camel_case_types)]
pub type dispatch_queue_t = *mut dispatch_object_s;
#[allow(non_camel_case_types)]
pub type dispatch_queue_attr_t = *const dispatch_object_s;

extern "C" {
    static _dispatch_queue_attr_concurrent: dispatch_object_s;

    pub fn dispatch_queue_create(
        label: *const c_char,
        attr: dispatch_queue_attr_t,
    ) -> dispatch_queue_t;

    pub fn dispatch_async_f(
        queue: dispatch_queue_t,
        context: *mut c_void,
        work: dispatch_function_t,
    );
    pub fn dispatch_async(queue: dispatch_queue_t, block: &Block<dyn Fn()>);
    pub fn dispatch_sync_f(
        queue: dispatch_queue_t,
        context: *mut c_void,
        work: dispatch_function_t,
    );
    pub fn dispatch_sync(queue: dispatch_queue_t, block: &Block<dyn Fn()>);

    pub fn dispatch_release(object: dispatch_object_t);
    pub fn dispatch_resume(object: dispatch_object_t);
    pub fn dispatch_retain(object: dispatch_object_t);
    pub fn dispatch_suspend(object: dispatch_object_t);
}

pub const DISPATCH_QUEUE_SERIAL: dispatch_queue_attr_t = 0 as dispatch_queue_attr_t;
pub static DISPATCH_QUEUE_CONCURRENT: &dispatch_object_s =
    unsafe { &_dispatch_queue_attr_concurrent };

fn context_and_function<F>(closure: F) -> (*mut c_void, dispatch_function_t)
where
    F: FnOnce(),
{
    extern "C" fn work_execute_closure<F>(context: Box<F>)
    where
        F: FnOnce(),
    {
        (*context)();
    }

    let closure = Box::new(closure);
    let func: extern "C" fn(Box<F>) = work_execute_closure::<F>;
    unsafe {
        (
            mem::transmute::<Box<F>, *mut c_void>(closure),
            mem::transmute::<extern "C" fn(Box<F>), dispatch_function_t>(func),
        )
    }
}

fn context_and_sync_function<F>(closure: &mut Option<F>) -> (*mut c_void, dispatch_function_t)
where
    F: FnOnce(),
{
    extern "C" fn work_read_closure<F>(context: &mut Option<F>)
    where
        F: FnOnce(),
    {
        // This is always passed Some, so it's safe to unwrap
        let closure = context.take().unwrap();
        closure();
    }

    let context: *mut Option<F> = closure;
    let func: extern "C" fn(&mut Option<F>) = work_read_closure::<F>;
    unsafe {
        (
            context as *mut c_void,
            mem::transmute::<extern "C" fn(&mut Option<F>), dispatch_function_t>(func),
        )
    }
}

/// The type of a dispatch queue.
#[derive(Clone, Debug, Hash, PartialEq)]
pub enum QueueAttribute {
    /// The queue executes blocks serially in FIFO order.
    Serial,
    /// The queue executes blocks concurrently.
    #[allow(dead_code)]
    Concurrent,
}

impl QueueAttribute {
    fn as_raw(&self) -> dispatch_queue_attr_t {
        match *self {
            QueueAttribute::Serial => DISPATCH_QUEUE_SERIAL,
            QueueAttribute::Concurrent => DISPATCH_QUEUE_CONCURRENT,
        }
    }
}

/// A Grand Central Dispatch queue.
#[derive(Debug)]
pub struct Queue {
    pub(crate) ptr: dispatch_queue_t,
}

impl Queue {
    /// Creates a new dispatch `Queue`.
    pub fn create(label: &str, attr: QueueAttribute) -> Self {
        let label = CString::new(label).unwrap();
        let queue = unsafe { dispatch_queue_create(label.as_ptr(), attr.as_raw()) };
        Queue { ptr: queue }
    }

    /// Returns a reference usable as a `dispatch2::DispatchQueue`.
    ///
    /// # Safety
    ///
    /// `dispatch2::DispatchQueue` is an opaque `#[repr(C)]` type used behind references.
    /// Our `dispatch_queue_t` pointer points to the same underlying dispatch queue object,
    /// so we can reinterpret it as `&DispatchQueue`.
    pub(crate) unsafe fn as_dispatch2(&self) -> &dispatch2::DispatchQueue {
        &*(self.ptr as *const dispatch2::DispatchQueue)
    }

    /// Submits a closure for execution on self and waits until it completes.
    #[allow(dead_code)]
    pub fn exec_sync<T, F>(&self, work: F) -> T
    where
        F: Send + FnOnce() -> T,
        T: Send,
    {
        let mut result = None;
        {
            let result_ref = &mut result;
            let work = move || {
                *result_ref = Some(work());
            };

            let mut work = Some(work);
            let (context, work) = context_and_sync_function(&mut work);
            unsafe {
                dispatch_sync_f(self.ptr, context, work);
            }
        }
        // This was set so it's safe to unwrap
        result.unwrap()
    }

    /// Submits a closure for asynchronous execution on self and returns
    /// immediately.
    #[allow(dead_code)]
    pub fn exec_async<F>(&self, work: F)
    where
        F: 'static + Send + FnOnce(),
    {
        let (context, work) = context_and_function(work);
        unsafe {
            dispatch_async_f(self.ptr, context, work);
        }
    }

    #[allow(dead_code)]
    pub fn exec_block_async(&self, block: &Block<dyn Fn()>) {
        unsafe {
            dispatch_async(self.ptr, block);
        }
    }

    #[allow(dead_code)]
    pub fn exec_block_sync(&self, block: &Block<dyn Fn()>) {
        unsafe {
            dispatch_sync(self.ptr, block);
        }
    }

    /// Suspends the invocation of blocks on self and returns a `SuspendGuard`
    /// that can be dropped to resume.
    #[allow(dead_code)]
    pub fn suspend(&self) -> SuspendGuard {
        SuspendGuard::new(self)
    }
}

unsafe impl Sync for Queue {}
unsafe impl Send for Queue {}

impl Clone for Queue {
    fn clone(&self) -> Self {
        unsafe {
            dispatch_retain(self.ptr);
        }
        Queue { ptr: self.ptr }
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        unsafe {
            dispatch_release(self.ptr);
        }
    }
}

/// An RAII guard which will resume a suspended `Queue` when dropped.
#[derive(Debug)]
pub struct SuspendGuard {
    queue: Queue,
}

impl SuspendGuard {
    fn new(queue: &Queue) -> SuspendGuard {
        unsafe {
            dispatch_suspend(queue.ptr);
        }
        SuspendGuard {
            queue: queue.clone(),
        }
    }

    /// Drops self, allowing the suspended `Queue` to resume.
    #[allow(dead_code)]
    pub fn resume(self) {}
}

impl Clone for SuspendGuard {
    fn clone(&self) -> Self {
        SuspendGuard::new(&self.queue)
    }
}

impl Drop for SuspendGuard {
    fn drop(&mut self) {
        unsafe {
            dispatch_resume(self.queue.ptr);
        }
    }
}
