use std::slice;

use crate::{
    generate_identity_keypair, generate_one_time_prekey, generate_signed_prekey, sign_message,
};

const FFI_OK: i32 = 0;
const FFI_INVALID_ARGUMENT: i32 = 1;
const FFI_OUTPUT_TOO_SMALL: i32 = 2;

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
