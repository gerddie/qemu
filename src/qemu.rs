#![crate_type = "staticlib"]
extern crate libc;
use libc::{size_t, c_char, c_void};
use std::mem;
use std::ffi::CString;

#[allow(dead_code)]
enum ModuleInit {
    BLOCK,
    OPTS,
    QAPI,
    QOM,
    MAX
}

pub enum Object {}
pub enum ObjectClass {}

#[repr(C)]
#[allow(dead_code)]
struct InterfaceInfo
{
    pub itype: *const c_char,
}

#[repr(C)]
#[allow(dead_code)]
struct TypeInfo
{
    pub name: *const c_char,
    pub parent: *const c_char,

    pub instance_size: size_t,
    pub instance_init: Option<extern fn(obj: *mut Object)>,
    pub instance_post_init: Option<extern fn(obj: *mut Object)>,
    pub instance_finalize: Option<extern fn(obj: *mut Object)>,

    pub abstrakt: bool,
    pub class_size: size_t,

    pub class_init: Option<extern fn(klass: *mut ObjectClass, data: *mut c_void)>,
    pub class_base_init: Option<extern fn(klass: *mut ObjectClass, data: *mut c_void)>,
    pub class_finalize: Option<extern fn(klass: *mut ObjectClass, data: *mut c_void)>,

    pub class_data: *const c_void,

    pub interfaces: *const InterfaceInfo
}

macro_rules! c_str {
    ($s:expr) => { {
        concat!($s, "\0").as_ptr() as *const i8
    } }
}

impl Default for TypeInfo {
    fn default () -> TypeInfo {
        TypeInfo {
            name: CString::new("Hello, world!").unwrap().as_ptr(),
            parent: CString::new("Hello, world!").unwrap().as_ptr(),
            instance_size: 0,
            instance_init: None,
            instance_post_init: None,
            instance_finalize: None,
            abstrakt: false,
            class_size: 0,
            class_init: None,
            class_base_init: None,
            class_finalize: None,
            class_data: std::ptr::null(),
            interfaces: std::ptr::null()
        }
    }
}


extern {
    fn register_module_init(cb: extern fn(), module_init_type: i32);
}

static foo: TypeInfo { ..Default::default() };

extern fn init_types() {
    foo.instance_size = mem::size_of::<i32>();

//    type_register()
}

#[no_mangle]
pub extern fn qemu_rust_init() {
    unsafe {
        register_module_init(init_types, ModuleInit::QOM as i32);
    }
}
