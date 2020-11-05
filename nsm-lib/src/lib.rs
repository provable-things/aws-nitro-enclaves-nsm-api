// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! ***NitroSecureModule wrappers for non-Rust callers***
//! # Overview
//! This module implements wrappers over the NSM Rust API which enable
//! access to the API for non-Rust callers (ex.: C/C++ etc.).

use nsm_driver::{nsm_exit, nsm_init, nsm_process_request};
use nsm_driver::{nsm_get_raw_from_vec, nsm_get_vec_from_raw};
use nsm_io::{Digest, ErrorCode, Request, Response};
use serde_bytes::ByteBuf;
use std::cmp;
use std::ptr;

use cpython::{PyResult, Python, py_module_initializer, py_fn, PyBytes};

py_module_initializer!(libnsm, |py, m| {
    m.add(py, "__doc__", "This module is implemented in Rust.")?;
    m.add(py, "nsm_lib_init", py_fn!(py, nsm_lib_init_py()))?;
    m.add(py, "nsm_lib_exit", py_fn!(py, nsm_lib_exit_py(fd: i32)))?;
    m.add(py, "nsm_get_random", py_fn!(py, nsm_get_random_py(fd: i32, length: i32)))?;
    m.add(py, "nsm_get_attestation_doc", py_fn!(py, nsm_get_attestation_doc_py(
        fd: i32,
        pub_key_data: PyBytes,
        pub_key_len: u32,
    )))?;
    Ok(())
});

fn nsm_lib_init_py(_: Python) -> PyResult<i32> {
    let out = nsm_init();
    Ok(out)
}

fn nsm_lib_exit_py(_: Python, fd: i32) -> PyResult<i32> {
    nsm_exit(fd);
    Ok(0)
}

unsafe fn nsm_get_random_py(py: Python, fd: i32, length: i32) -> PyResult<PyBytes> {
    let buf_len: &mut usize = &mut 0;

    let mut buf = vec![0; length as usize];
    let buf_ptr = buf.as_mut_ptr();
    *buf_len = buf.len();

    match nsm_process_request(fd, Request::GetRandom) {
        Response::GetRandom { random } => {
            *buf_len = std::cmp::min(*buf_len, random.len());
            std::ptr::copy_nonoverlapping(random.as_ptr(), buf_ptr, *buf_len);
            ErrorCode::Success
        }
        Response::Error(err) => err,
        _ => ErrorCode::InvalidResponse,
    };
    Ok(PyBytes::new(py, &buf))
}

unsafe fn nsm_get_attestation_doc_py(
    py: Python,
    fd: i32,
    pub_key_data: PyBytes,
    pub_key_len: u32,
) -> PyResult<PyBytes> {
    let user_data: *const u8 = ptr::null();
    let user_data_len = 0;
    let nonce_data: *const u8 = ptr::null();
    let nonce_len = 0;
    let pub_key_data_rust = pub_key_data.data(py);
    let pub_key_data_ptr = pub_key_data_rust.as_ptr();

    let mut buffer = vec![0; 16 * 1024];
    let att_doc_data = buffer.as_mut_ptr();
    let att_doc_len: &mut u32 = &mut (16 * 1024);

    let request = Request::Attestation {
        user_data: get_byte_buf_from_user_data(user_data, user_data_len),
        nonce: get_byte_buf_from_user_data(nonce_data, nonce_len),
        public_key: get_byte_buf_from_user_data(pub_key_data_ptr, pub_key_len),
    };

    match nsm_process_request(fd, request) {
        Response::Attestation {
            document: attestation_doc,
        } => nsm_get_raw_from_vec(&attestation_doc, att_doc_data, att_doc_len),
        Response::Error(err) => err,
        _ => ErrorCode::InvalidResponse,
    };

    Ok(PyBytes::new(py, &buffer[..(*att_doc_len as usize)]))
}

#[repr(C)]
pub struct NsmDescription {
    pub version_major: u16,
    pub version_minor: u16,
    pub version_patch: u16,
    pub module_id: [u8; 100],
    pub module_id_len: u32,
    pub max_pcrs: u16,
    pub locked_pcrs: [u16; 64],
    pub locked_pcrs_len: u32,
    pub digest: Digest,
}

/// NSM library initialization function.  
/// *Returns*: A descriptor for the opened device file.
#[no_mangle]
pub extern "C" fn nsm_lib_init() -> i32 {
    nsm_init()
}

/// NSM library exit function.  
/// *Argument 1 (input)*: The descriptor for the opened device file, as
/// obtained from `nsm_init()`.
#[no_mangle]
pub extern "C" fn nsm_lib_exit(fd: i32) {
    nsm_exit(fd)
}

/// NSM `ExtendPCR` operation for non-Rust callers.  
/// *Argument 1 (input)*: The descriptor to the NSM device file.  
/// *Argument 2 (input)*: The index of the PCR to extend.  
/// *Argument 3 (input)*: The raw data to extend the PCR with.  
/// *Argument 4 (input)*: The length of the raw data, in bytes.  
/// *Argument 5 (output)*: The data from the extended PCR.  
/// *Argument 6 (input/output)*: The capacity of the extended PCR data
/// buffer as input, the actual size of the buffer as output.  
/// *Returns*: The status of the operation.
#[no_mangle]
pub unsafe extern "C" fn nsm_extend_pcr(
    fd: i32,
    index: u16,
    data: *const u8,
    data_len: u32,
    pcr_data: *mut u8,
    pcr_data_len: &mut u32,
) -> ErrorCode {
    let data_vec = nsm_get_vec_from_raw(data, data_len);
    match data_vec {
        Some(_) => (),
        None => return ErrorCode::InvalidArgument,
    }

    let request = Request::ExtendPCR {
        index,
        data: data_vec.unwrap(),
    };

    match nsm_process_request(fd, request) {
        Response::ExtendPCR { data: pcr } => nsm_get_raw_from_vec(&pcr, pcr_data, pcr_data_len),
        Response::Error(err) => err,
        _ => ErrorCode::InvalidResponse,
    }
}

/// NSM `DescribePCR` operation for non-Rust callers.  
/// *Argument 1 (input)*: The descriptor to the NSM device file.  
/// *Argument 2 (input)*: The index of the PCR to be described.  
/// *Argument 3 (output)*: The lock state of the PCR.  
/// *Argument 4 (output)*: The buffer that will hold the PCR data.    
/// *Argument 5 (input / output)*: The PCR data buffer capacity (as input)
/// and the actual size of the received data (as output).  
/// *Returns*: The status of the operation.
#[no_mangle]
pub unsafe extern "C" fn nsm_describe_pcr(
    fd: i32,
    index: u16,
    lock: &mut bool,
    data: *mut u8,
    data_len: &mut u32,
) -> ErrorCode {
    let request = Request::DescribePCR { index };

    match nsm_process_request(fd, request) {
        Response::DescribePCR {
            lock: pcr_lock,
            data: pcr_data,
        } => {
            *lock = pcr_lock;
            nsm_get_raw_from_vec(&pcr_data, data, data_len)
        }
        Response::Error(err) => err,
        _ => ErrorCode::InvalidResponse,
    }
}

/// NSM `LockPCR` operation for non-Rust callers.  
/// *Argument 1 (input)*: The descriptor to the NSM device file.  
/// *Argument 2 (input)*: The PCR to be locked.  
/// *Returns*: The status of the operation.
#[no_mangle]
pub extern "C" fn nsm_lock_pcr(fd: i32, index: u16) -> ErrorCode {
    let request = Request::LockPCR { index };

    match nsm_process_request(fd, request) {
        Response::LockPCR => ErrorCode::Success,
        Response::Error(err) => err,
        _ => ErrorCode::InvalidResponse,
    }
}

/// NSM `LockPCRs` operation for non-Rust callers.  
/// *Argument 1 (input)*: The descriptor to the NSM device file.  
/// *Argument 2 (input)*: The range value for `[0, range)` to be locked.  
/// *Returns*: The status of the operation.
#[no_mangle]
pub extern "C" fn nsm_lock_pcrs(fd: i32, range: u16) -> ErrorCode {
    let request = Request::LockPCRs { range };

    match nsm_process_request(fd, request) {
        Response::LockPCRs => ErrorCode::Success,
        Response::Error(err) => err,
        _ => ErrorCode::InvalidResponse,
    }
}

/// NSM `Describe` operation for non-Rust callers.  
/// *Argument 1 (input)*: The descriptor to the NSM device file.  
/// *Argument 2 (output)*: The obtained raw NSM description.  
/// *Returns*: The status of the operation.
#[no_mangle]
pub extern "C" fn nsm_get_description(fd: i32, nsm_description: &mut NsmDescription) -> ErrorCode {
    let request = Request::DescribeNSM;

    match nsm_process_request(fd, request) {
        Response::DescribeNSM {
            version_major,
            version_minor,
            version_patch,
            module_id,
            max_pcrs,
            locked_pcrs,
            digest,
        } => {
            nsm_description.version_major = version_major;
            nsm_description.version_minor = version_minor;
            nsm_description.version_patch = version_patch;
            nsm_description.max_pcrs = max_pcrs;

            match digest {
                Digest::SHA256 => {
                    nsm_description.digest = Digest::SHA256;
                }
                Digest::SHA384 => {
                    nsm_description.digest = Digest::SHA384;
                }
                Digest::SHA512 => {
                    nsm_description.digest = Digest::SHA512;
                }
            }
            nsm_description.locked_pcrs_len = locked_pcrs.len() as u32;

            for (i, val) in locked_pcrs.iter().enumerate() {
                nsm_description.locked_pcrs[i] = *val;
            }

            let module_id_len = cmp::min(nsm_description.module_id.len() - 1, module_id.len());
            nsm_description.module_id[0..module_id_len]
                .copy_from_slice(&module_id.as_bytes()[0..module_id_len]);
            nsm_description.module_id[module_id_len] = 0;
            nsm_description.module_id_len = module_id_len as u32;

            ErrorCode::Success
        }
        Response::Error(err) => err,
        _ => ErrorCode::InvalidResponse,
    }
}

/// Get an optional byte buffer from user data.  
/// *Argument 1 (input)*: User data.  
/// *Argument 2 (input)*: Size of the user data buffer.  
/// *Returns*: The optional byte buffer.
unsafe fn get_byte_buf_from_user_data(data: *const u8, len: u32) -> Option<ByteBuf> {
    let data_vec = nsm_get_vec_from_raw(data, len);
    match data_vec {
        Some(buffer) => Some(ByteBuf::from(buffer)),
        None => None,
    }
}

/// NSM `GetAttestationDoc` operation for non-Rust callers.  
/// *Argument 1 (input)*: The descriptor to the NSM device file.  
/// *Argument 2 (input)*: User data.  
/// *Argument 3 (input)*: The size of the user data buffer.  
/// *Argument 4 (input)*: Nonce data.  
/// *Argument 5 (input)*: The size of the nonce data buffer.  
/// *Argument 6 (input)*: Public key data.  
/// *Argument 7 (input)*: The size of the public key data buffer.  
/// *Argument 8 (output)*: The obtained attestation document.  
/// *Argument 9 (input / output)*: The document buffer capacity (as input)
/// and the size of the received document (as output).  
/// *Returns*: The status of the operation.
#[no_mangle]
pub unsafe extern "C" fn nsm_get_attestation_doc(
    fd: i32,
    user_data: *const u8,
    user_data_len: u32,
    nonce_data: *const u8,
    nonce_len: u32,
    pub_key_data: *const u8,
    pub_key_len: u32,
    att_doc_data: *mut u8,
    att_doc_len: &mut u32,
) -> ErrorCode {
    let request = Request::Attestation {
        user_data: get_byte_buf_from_user_data(user_data, user_data_len),
        nonce: get_byte_buf_from_user_data(nonce_data, nonce_len),
        public_key: get_byte_buf_from_user_data(pub_key_data, pub_key_len),
    };

    match nsm_process_request(fd, request) {
        Response::Attestation {
            document: attestation_doc,
        } => nsm_get_raw_from_vec(&attestation_doc, att_doc_data, att_doc_len),
        Response::Error(err) => err,
        _ => ErrorCode::InvalidResponse,
    }
}

/// NSM `GetRandom` operation for non-Rust callers. Returns up to 256 bytes of random data.
/// *fd (input)*: A valid descriptor to the NSM device.
/// *buf (output)*: A valid buffer to place the random data in.
/// *buf_len (input / output)*: The length of the passed buffer and the length of the output data
///                             if the function finishes with ErrorCode::Success.
#[no_mangle]
pub unsafe extern "C" fn nsm_get_random(fd: i32, buf: *mut u8, buf_len: &mut usize) -> ErrorCode {
    if fd < 0 || buf.is_null() || buf_len == &0 {
        return ErrorCode::InvalidArgument;
    }
    match nsm_process_request(fd, Request::GetRandom) {
        Response::GetRandom { random } => {
            *buf_len = std::cmp::min(*buf_len, random.len());
            std::ptr::copy_nonoverlapping(random.as_ptr(), buf, *buf_len);
            ErrorCode::Success
        }
        Response::Error(err) => err,
        _ => ErrorCode::InvalidResponse,
    }
}
