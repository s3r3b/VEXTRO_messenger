use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::slice;

use serde::Serialize;

use crate::{
    generate_identity_keypair, generate_one_time_prekey, generate_signed_prekey, sign_message,
};

#[cfg(target_os = "android")]
mod android_jni {
    use super::*;
    use jni::objects::{JObject, JString};
    use jni::sys::jint;
    use jni::JNIEnv;

    fn call_json<T>(env: &mut JNIEnv<'_>, result: T) -> Option<jni::sys::jstring>
    where
        T: FnOnce() -> *const c_char,
    {
        let pointer = result();
        if pointer.is_null() {
            return None;
        }
        let json = unsafe { CStr::from_ptr(pointer).to_string_lossy().into_owned() };
        unsafe { vextro_facade_free_string(pointer as *mut c_char) };
        env.new_string(json).ok().map(|value| value.into_raw())
    }

    #[no_mangle]
    pub extern "system" fn Java_com_vextro_messenger_VextroCryptoModule_nativeCreatePrekeyBundle(
        mut env: JNIEnv<'_>,
        _object: JObject<'_>,
        opk_count: jint,
    ) -> jni::sys::jstring {
        call_json(&mut env, || {
            vextro_facade_create_prekey_bundle(opk_count.max(0) as u32)
        })
        .unwrap_or(std::ptr::null_mut())
    }

    macro_rules! jni_string_method {
        ($name:ident, $rust_fn:ident, $first:ident, $second:ident) => {
            #[no_mangle]
            pub extern "system" fn $name(
                mut env: JNIEnv<'_>,
                _object: JObject<'_>,
                first: JString<'_>,
                second: JString<'_>,
            ) -> jni::sys::jstring {
                let first = match env.get_string(&first) {
                    Ok(value) => value.to_string_lossy().into_owned(),
                    Err(_) => return std::ptr::null_mut(),
                };
                let second = match env.get_string(&second) {
                    Ok(value) => value.to_string_lossy().into_owned(),
                    Err(_) => return std::ptr::null_mut(),
                };
                let first = match CString::new(first) {
                    Ok(value) => value,
                    Err(_) => return std::ptr::null_mut(),
                };
                let second = match CString::new(second) {
                    Ok(value) => value,
                    Err(_) => return std::ptr::null_mut(),
                };
                call_json(&mut env, || unsafe {
                    $rust_fn(first.as_ptr(), second.as_ptr())
                })
                .unwrap_or(std::ptr::null_mut())
            }
        };
    }

    jni_string_method!(
        Java_com_vextro_messenger_VextroCryptoModule_nativeInitOutboundSession,
        vextro_facade_init_outbound_session,
        bundle,
        secret
    );
    jni_string_method!(
        Java_com_vextro_messenger_VextroCryptoModule_nativeInitInboundSession,
        vextro_facade_init_inbound_session,
        message,
        keys
    );
    jni_string_method!(
        Java_com_vextro_messenger_VextroCryptoModule_nativeEncryptMessage,
        vextro_facade_encrypt_message,
        state,
        plaintext
    );
    jni_string_method!(
        Java_com_vextro_messenger_VextroCryptoModule_nativeDecryptMessage,
        vextro_facade_decrypt_message,
        state,
        payload
    );
}

const FFI_OK: i32 = 0;
const FFI_INVALID_ARGUMENT: i32 = 1;
const FFI_OUTPUT_TOO_SMALL: i32 = 2;

unsafe fn read_string<'a>(value: *const c_char) -> Result<&'a str, ()> {
    if value.is_null() {
        return Err(());
    }
    CStr::from_ptr(value).to_str().map_err(|_| ())
}

fn return_json<T: Serialize>(value: Result<T, String>) -> *const c_char {
    match value.and_then(|value| serde_json::to_string(&value).map_err(|error| error.to_string())) {
        Ok(json) => CString::new(json).map_or(std::ptr::null(), |json| json.into_raw()),
        Err(_) => std::ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn vextro_facade_free_string(value: *mut c_char) {
    if !value.is_null() {
        drop(CString::from_raw(value));
    }
}

#[no_mangle]
pub extern "C" fn vextro_facade_create_prekey_bundle(opk_count: u32) -> *const c_char {
    return_json(crate::facade::create_prekey_bundle(opk_count))
}

#[no_mangle]
pub unsafe extern "C" fn vextro_facade_init_outbound_session(
    bob_bundle_json: *const c_char,
    my_identity_secret: *const c_char,
) -> *const c_char {
    let bundle = match read_string(bob_bundle_json) {
        Ok(value) => value,
        Err(_) => return std::ptr::null(),
    };
    let secret = match read_string(my_identity_secret) {
        Ok(value) => value,
        Err(_) => return std::ptr::null(),
    };
    return_json(crate::facade::init_outbound_session(bundle, secret))
}

#[no_mangle]
pub unsafe extern "C" fn vextro_facade_init_inbound_session(
    initial_msg_json: *const c_char,
    my_keys_json: *const c_char,
) -> *const c_char {
    let message = match read_string(initial_msg_json) {
        Ok(value) => value,
        Err(_) => return std::ptr::null(),
    };
    let keys = match read_string(my_keys_json) {
        Ok(value) => value,
        Err(_) => return std::ptr::null(),
    };
    return_json(crate::facade::init_inbound_session(message, keys))
}

#[no_mangle]
pub unsafe extern "C" fn vextro_facade_encrypt_message(
    session_state_json: *const c_char,
    plaintext: *const c_char,
) -> *const c_char {
    let state = match read_string(session_state_json) {
        Ok(value) => value,
        Err(_) => return std::ptr::null(),
    };
    let plaintext = match read_string(plaintext) {
        Ok(value) => value,
        Err(_) => return std::ptr::null(),
    };
    return_json(crate::facade::encrypt_message(state, plaintext))
}

#[no_mangle]
pub unsafe extern "C" fn vextro_facade_decrypt_message(
    session_state_json: *const c_char,
    message_payload_json: *const c_char,
) -> *const c_char {
    let state = match read_string(session_state_json) {
        Ok(value) => value,
        Err(_) => return std::ptr::null(),
    };
    let payload = match read_string(message_payload_json) {
        Ok(value) => value,
        Err(_) => return std::ptr::null(),
    };
    return_json(crate::facade::decrypt_message(state, payload))
}

#[no_mangle]
pub extern "C" fn vextro_crypto_version() -> u32 {
    1
}

#[no_mangle]
pub unsafe extern "C" fn vextro_generate_identity_keypair(
    public_key_out: *mut u8,
    public_key_capacity: usize,
    private_key_out: *mut u8,
    private_key_capacity: usize,
) -> i32 {
    write_keypair(
        generate_identity_keypair(),
        public_key_out,
        public_key_capacity,
        private_key_out,
        private_key_capacity,
    )
}

#[no_mangle]
pub unsafe extern "C" fn vextro_generate_signed_prekey(
    public_key_out: *mut u8,
    public_key_capacity: usize,
    private_key_out: *mut u8,
    private_key_capacity: usize,
) -> i32 {
    write_keypair(
        generate_signed_prekey(),
        public_key_out,
        public_key_capacity,
        private_key_out,
        private_key_capacity,
    )
}

#[no_mangle]
pub unsafe extern "C" fn vextro_generate_one_time_prekey(
    public_key_out: *mut u8,
    public_key_capacity: usize,
    private_key_out: *mut u8,
    private_key_capacity: usize,
) -> i32 {
    write_keypair(
        generate_one_time_prekey(),
        public_key_out,
        public_key_capacity,
        private_key_out,
        private_key_capacity,
    )
}

#[no_mangle]
pub unsafe extern "C" fn vextro_sign(
    message: *const u8,
    message_len: usize,
    private_key: *const u8,
    private_key_len: usize,
    signature_out: *mut u8,
    signature_capacity: usize,
) -> i32 {
    if message.is_null() || private_key.is_null() || signature_out.is_null() {
        return FFI_INVALID_ARGUMENT;
    }

    let message = slice::from_raw_parts(message, message_len);
    let private_key = slice::from_raw_parts(private_key, private_key_len);
    let signature = sign_message(message, private_key);
    if signature.len() > signature_capacity {
        return FFI_OUTPUT_TOO_SMALL;
    }

    std::ptr::copy_nonoverlapping(signature.as_ptr(), signature_out, signature.len());
    FFI_OK
}

unsafe fn write_keypair(
    key_pair: crate::KeyPair,
    public_key_out: *mut u8,
    public_key_capacity: usize,
    private_key_out: *mut u8,
    private_key_capacity: usize,
) -> i32 {
    if public_key_out.is_null() || private_key_out.is_null() {
        return FFI_INVALID_ARGUMENT;
    }
    if key_pair.public_key.len() > public_key_capacity
        || key_pair.private_key.len() > private_key_capacity
    {
        return FFI_OUTPUT_TOO_SMALL;
    }

    std::ptr::copy_nonoverlapping(
        key_pair.public_key.as_ptr(),
        public_key_out,
        key_pair.public_key.len(),
    );
    std::ptr::copy_nonoverlapping(
        key_pair.private_key.as_ptr(),
        private_key_out,
        key_pair.private_key.len(),
    );
    FFI_OK
}
