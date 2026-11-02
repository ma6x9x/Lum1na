//! lumina_core — C ABI for Mach-O self-test, trustcache parse, UCB1, ANE arm
//! map, and AfterKread step names.
//!
//! IPA links the C translation in `Exploit/lumina_core.c` (CI has no rustc).
//! Keep this file and that C file in lockstep. No IOKit.

use std::ffi::{c_char, c_int, CStr};
use std::os::raw::c_void;
use std::ptr;

pub const LUMINA_CORE_VERSION: &str = "lumina-core-v2\0";
pub const LUMINA_MH_MAGIC_64: u32 = 0xfeed_facf;
pub const LUMINA_MH_MAGIC_CPUTYPE: u64 = 0x0100_000c_feed_facf;
pub const LUMINA_MH_TYPEINFO_ARM64: u64 = 0x0000_0002_0000_0000;
pub const LUMINA_MH_TYPEINFO_ARM64E: u64 = 0x0000_000c_0000_0002;
pub const LUMINA_MH_TYPEINFO_ARM64E19: u64 = 0x0000_000c_c000_0002;
pub const LUMINA_PAGE_SIZE: usize = 0x4000;
pub const LUMINA_TC_HASH_LEN: usize = 20;
pub const LUMINA_TC_ENTRY_SIZE: usize = 22;
pub const LUMINA_TC_HEADER_SIZE: usize = 24;
pub const LUMINA_TC_MAX_ENTRIES: u32 = 4096;
pub const LUMINA_SLIDE_MAX: u64 = 0x1_0000_0000;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct lumina_tc_info {
    pub version: u32,
    pub length: u32,
    pub nentries: u32,
    pub ok: c_int,
}

#[no_mangle]
pub extern "C" fn lumina_mh_magic32_ok(magic: u32) -> c_int {
    (magic == LUMINA_MH_MAGIC_64) as c_int
}

#[no_mangle]
pub extern "C" fn lumina_mh_magic64_ok(magic64: u64) -> c_int {
    (magic64 == LUMINA_MH_MAGIC_CPUTYPE) as c_int
}

#[no_mangle]
pub extern "C" fn lumina_mh_typeinfo_ok(typeinfo: u64) -> c_int {
    (typeinfo == LUMINA_MH_TYPEINFO_ARM64
        || typeinfo == LUMINA_MH_TYPEINFO_ARM64E
        || typeinfo == LUMINA_MH_TYPEINFO_ARM64E19) as c_int
}

#[no_mangle]
pub extern "C" fn lumina_slide_in_range(slide: u64) -> c_int {
    (slide <= LUMINA_SLIDE_MAX) as c_int
}

#[no_mangle]
pub extern "C" fn lumina_slide_live(slide: u64) -> c_int {
    (slide != 0 && slide <= LUMINA_SLIDE_MAX) as c_int
}

#[no_mangle]
pub extern "C" fn lumina_kbase_from_slide(static_base: u64, slide: u64) -> u64 {
    if lumina_slide_in_range(slide) == 0 {
        return 0;
    }
    static_base.wrapping_add(slide)
}

#[no_mangle]
pub extern "C" fn lumina_kptr_zone(v: u64) -> c_int {
    (v >= 0xFFFF_FFE0_0000_0000 && v < 0xFFFF_FFF0_0000_0000) as c_int
}

#[no_mangle]
pub extern "C" fn lumina_kptr_static(v: u64) -> c_int {
    (v >= 0xFFFF_FFF0_0000_0000) as c_int
}

#[no_mangle]
pub unsafe extern "C" fn lumina_trustcache_parse(
    blob: *const c_void,
    len: usize,
    out: *mut lumina_tc_info,
) -> c_int {
    if !out.is_null() {
        *out = lumina_tc_info::default();
    }
    if blob.is_null() || len < LUMINA_TC_HEADER_SIZE {
        return -1;
    }
    let p = blob as *const u8;
    let version = u32::from_le_bytes([*p, *p.add(1), *p.add(2), *p.add(3)]);
    let length = u32::from_le_bytes([*p.add(20), *p.add(21), *p.add(22), *p.add(23)]);
    if version != 1 {
        return -2;
    }
    if length > LUMINA_TC_MAX_ENTRIES {
        return -3;
    }
    let need = LUMINA_TC_HEADER_SIZE + (length as usize) * LUMINA_TC_ENTRY_SIZE;
    if need != len {
        return -4;
    }
    if !out.is_null() {
        *out = lumina_tc_info {
            version,
            length,
            nentries: length,
            ok: 1,
        };
    }
    0
}

fn cstr<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p) }.to_str().ok()
}

#[no_mangle]
pub extern "C" fn lumina_bandit_reward(outcome: *const c_char) -> f64 {
    match cstr(outcome).unwrap_or("") {
        "door" | "claim-won" | "ok" | "conversion" | "magic" | "fault-with-far" => 1.0,
        "maf" | "family-b" => 0.0,
        "abort" | "fires" | "occupancy" => 0.5,
        _ => 0.25,
    }
}

#[no_mangle]
pub extern "C" fn lumina_ucb1(mean: f64, n_i: f64, mut n: f64) -> f64 {
    if n_i <= 0.0 {
        return 1e9;
    }
    if n < 1.0 {
        n = 1.0;
    }
    mean + ((2.0 * n.ln()) / n_i).sqrt()
}

#[no_mangle]
pub extern "C" fn lumina_ane_req_in_for_arm(arm: *const c_char) -> u32 {
    match cstr(arm).unwrap_or("") {
        "oob192" => 192,
        "inb191" => 191,
        "small127" => 127,
        _ => 0,
    }
}

#[no_mangle]
pub extern "C" fn lumina_ane_model_for_arm(arm: *const c_char) -> *const c_char {
    match cstr(arm) {
        Some("small127") => b"XVRC27_127inmin_1out\0".as_ptr() as *const c_char,
        _ => ptr::null(),
    }
}

#[no_mangle]
pub extern "C" fn lumina_ane_record_count(req_in: u32) -> u32 {
    if !(2..=4096).contains(&req_in) {
        return 0;
    }
    req_in + 1
}

#[no_mangle]
pub extern "C" fn lumina_ane_oob_records(req_in: u32, cap: u32) -> u32 {
    let rec = lumina_ane_record_count(req_in);
    if rec == 0 || cap == 0 {
        return 0;
    }
    if rec > cap {
        rec - cap
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn lumina_ane_lock_oob192(conversion_confirmed: c_int) -> c_int {
    if conversion_confirmed != 0 {
        0
    } else {
        1
    }
}

#[no_mangle]
pub extern "C" fn lumina_ak_step_name(step: c_int) -> *const c_char {
    match step {
        0 => b"HOLD\0".as_ptr() as *const c_char,
        1 => b"SELFTEST\0".as_ptr() as *const c_char,
        2 => b"ELEVATE\0".as_ptr() as *const c_char,
        3 => b"PMAP_CS\0".as_ptr() as *const c_char,
        4 => b"TRUSTCACHE\0".as_ptr() as *const c_char,
        5 => b"INJECT\0".as_ptr() as *const c_char,
        6 => b"PKGMAN\0".as_ptr() as *const c_char,
        7 => b"RESPRING\0".as_ptr() as *const c_char,
        _ => b"?\0".as_ptr() as *const c_char,
    }
}

#[no_mangle]
pub extern "C" fn lumina_ak_next_step(
    has_kread: c_int,
    magic_ok: c_int,
    elevated: c_int,
    tc_loaded: c_int,
    injected: c_int,
) -> c_int {
    if has_kread == 0 || magic_ok == 0 {
        return 0; // HOLD
    }
    if elevated == 0 {
        return 2; // ELEVATE
    }
    if tc_loaded == 0 {
        return 4; // TRUSTCACHE
    }
    if injected == 0 {
        return 5; // INJECT
    }
    6 // PKGMAN
}

#[no_mangle]
pub extern "C" fn lumina_page_chunk(addr: u64, size: usize, page_size: usize) -> usize {
    if size == 0 || page_size == 0 {
        return 0;
    }
    let off = (addr as usize) & (page_size - 1);
    let room = page_size - off;
    if size < room {
        size
    } else {
        room
    }
}

#[no_mangle]
pub extern "C" fn lumina_core_version() -> *const c_char {
    LUMINA_CORE_VERSION.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn lumina_core_selftest() -> c_int {
    if lumina_mh_magic32_ok(0xfeed_facf) == 0 {
        return 1;
    }
    if lumina_mh_magic32_ok(0xfeed_face) != 0 {
        return 2;
    }
    if lumina_mh_magic64_ok(LUMINA_MH_MAGIC_CPUTYPE) == 0 {
        return 3;
    }
    if lumina_mh_typeinfo_ok(LUMINA_MH_TYPEINFO_ARM64) == 0 {
        return 4;
    }
    if lumina_mh_typeinfo_ok(LUMINA_MH_TYPEINFO_ARM64E) == 0 {
        return 5;
    }
    if lumina_mh_typeinfo_ok(LUMINA_MH_TYPEINFO_ARM64E19) == 0 {
        return 6;
    }
    if lumina_mh_typeinfo_ok(0x1b00_0000_00) != 0 {
        return 7;
    }
    if lumina_slide_in_range(0x1_0000_0000) == 0 {
        return 8;
    }
    if lumina_slide_in_range(0x1_0000_0001) != 0 {
        return 9;
    }
    if lumina_slide_live(0) != 0 {
        return 10;
    }
    if lumina_slide_live(0x123_4000) == 0 {
        return 11;
    }
    if lumina_kbase_from_slide(0xFFFF_FFF0_0700_4000, 0x123_4000)
        != 0xFFFF_FFF0_0700_4000 + 0x123_4000
    {
        return 12;
    }
    if lumina_kptr_zone(0xFFFF_FFE1_2340_0000) == 0 {
        return 13;
    }
    if lumina_kptr_static(0xFFFF_FFF0_0700_4000) == 0 {
        return 14;
    }
    if lumina_kptr_zone(0xFFFF_FFF0_0700_4000) != 0 {
        return 15;
    }

    let mut hdr = [0u8; LUMINA_TC_HEADER_SIZE];
    hdr[0] = 1;
    let mut info = lumina_tc_info::default();
    unsafe {
        if lumina_trustcache_parse(hdr.as_ptr() as *const c_void, hdr.len(), &mut info) != 0
            || info.ok == 0
        {
            return 16;
        }
        if info.version != 1 || info.length != 0 {
            return 17;
        }
        if lumina_trustcache_parse(
            hdr.as_ptr() as *const c_void,
            hdr.len() - 1,
            &mut info,
        ) == 0
        {
            return 18;
        }
    }

    if (lumina_bandit_reward(b"conversion\0".as_ptr() as *const c_char) - 1.0).abs() > 1e-12 {
        return 19;
    }
    if (lumina_bandit_reward(b"magic\0".as_ptr() as *const c_char) - 1.0).abs() > 1e-12 {
        return 20;
    }
    if (lumina_bandit_reward(b"occupancy\0".as_ptr() as *const c_char) - 0.5).abs() > 1e-12 {
        return 21;
    }
    if lumina_bandit_reward(b"maf\0".as_ptr() as *const c_char) != 0.0 {
        return 22;
    }
    if (lumina_bandit_reward(b"hold\0".as_ptr() as *const c_char) - 0.25).abs() > 1e-12 {
        return 23;
    }
    if lumina_ucb1(0.5, 0.0, 10.0) < 1e8 {
        return 24;
    }
    if lumina_ucb1(1.0, 4.0, 16.0) <= 1.0 {
        return 25;
    }

    if lumina_ane_req_in_for_arm(b"oob192\0".as_ptr() as *const c_char) != 192 {
        return 26;
    }
    if lumina_ane_req_in_for_arm(b"inb191\0".as_ptr() as *const c_char) != 191 {
        return 27;
    }
    if lumina_ane_req_in_for_arm(b"small127\0".as_ptr() as *const c_char) != 127 {
        return 28;
    }
    unsafe {
        let m = lumina_ane_model_for_arm(b"small127\0".as_ptr() as *const c_char);
        if m.is_null() || CStr::from_ptr(m).to_str().unwrap() != "XVRC27_127inmin_1out" {
            return 29;
        }
        if !lumina_ane_model_for_arm(b"oob192\0".as_ptr() as *const c_char).is_null() {
            return 30;
        }
        if lumina_ane_record_count(192) != 193 {
            return 40;
        }
        if lumina_ane_oob_records(192, 192) != 1 {
            return 41;
        }
        if lumina_ane_oob_records(191, 192) != 0 {
            return 42;
        }
        if lumina_ane_oob_records(192, 255) != 0 {
            return 43;
        }
        if lumina_ane_lock_oob192(0) != 1 {
            return 44;
        }
        if lumina_ane_lock_oob192(1) != 0 {
            return 45;
        }
        let hold = CStr::from_ptr(lumina_ak_step_name(0)).to_str().unwrap();
        if hold != "HOLD" {
            return 31;
        }
    }
    if lumina_ak_next_step(0, 0, 0, 0, 0) != 0 {
        return 32;
    }
    if lumina_ak_next_step(1, 1, 0, 0, 0) != 2 {
        return 33;
    }
    if lumina_ak_next_step(1, 1, 1, 0, 0) != 4 {
        return 34;
    }
    if lumina_ak_next_step(1, 1, 1, 1, 0) != 5 {
        return 35;
    }
    if lumina_ak_next_step(1, 1, 1, 1, 1) != 6 {
        return 36;
    }
    if lumina_page_chunk(0x1000, 0x2000, 0x4000) != 0x2000 {
        return 37;
    }
    if lumina_page_chunk(0x3000, 0x2000, 0x4000) != 0x1000 {
        return 38;
    }
    unsafe {
        if CStr::from_ptr(lumina_core_version()).to_str().unwrap() != "lumina-core-v2" {
            return 39;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selftest_passes() {
        assert_eq!(lumina_core_selftest(), 0);
    }
}
