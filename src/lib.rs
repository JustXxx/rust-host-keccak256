extern "C" {
    pub fn wasm_input(is_public: u32) -> u64;
    pub fn require(cond: bool);
    pub fn poseidon_new();
    pub fn keccak_new(v: u64);
    pub fn wasm_dbg_char(v: u64);
    pub fn keccak_push(v: u64);
    pub fn keccak_finalize() -> u64;
}

fn read_public_input() -> u64 {
    unsafe { wasm_input(1) }
}

fn read_private_input() -> u64 {
    unsafe { wasm_input(0) }
}

extern crate byteorder;
use byteorder::{BigEndian, ByteOrder};

fn u64_vec_to_u8_vec(input: Vec<u64>) -> Vec<u8> {
    let mut output = Vec::new();
    for num in input {
        let bytes = num.to_le_bytes();
        output.extend(bytes);
    }
    output
}

fn u8_vec_to_u64_vec(input: Vec<u8>) -> Vec<u64> {
    let mut output = input
        .chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<u64>>();
    let remainder = input.len() % 8;
    if remainder != 0 {
        let mut buffer = [0u8; 8];
        buffer[..remainder].copy_from_slice(&input[input.len() - remainder..]);
        let value = u64::from_le_bytes(buffer);
        output.push(value);
    }
    output
}

pub struct KeccakHasher (u64, u64, u64); // data, byte index in data (little), buf size
impl KeccakHasher {
    pub fn new() -> Self {
        unsafe {
            keccak_new(1u64);
        }
        KeccakHasher(0u64, 0u64, 0u64)
    }

    pub fn update_byte(&mut self, v: u8) {
        self.0 = self.0 + ((v as u64) << (self.1 * 8));
        self.1 = self.1 + 1;
        if self.1 >= 8 {
            unsafe {
                keccak_push(self.0);
            }
            self.0 = 0;
            self.1 = 0;

            self.2 = self.2 + 1;

            if self.2 == 17 {
                unsafe {
                    keccak_finalize();
                    keccak_finalize();
                    keccak_finalize();
                    keccak_finalize();
                    keccak_new(0u64);
                }
                self.2 = 0;
            }
        }
    }

    pub fn finalize(&mut self) -> [u64; 4] {
        let bytes_to_pad = 136 - self.1 - self.2 * 8;
        if bytes_to_pad == 1 {
            unsafe {
                keccak_push(self.0 + (0x81u64 << 56));
            }
        } else {
            self.update_byte(1);
            for _ in 0..bytes_to_pad-2 {
                self.update_byte(0);
            }
            unsafe {
                keccak_push(self.0 + (0x80u64 << 56));
            }
        }
        unsafe {
            [
                keccak_finalize(),
                keccak_finalize(),
                keccak_finalize(),
                keccak_finalize(),
            ]
        }
    }
}

pub fn keccak256(input: &Vec<u8>) -> Vec<u8> {
    let mut hasher = KeccakHasher::new();
    for d in input {
        hasher.update_byte(*d);
    }
    let keccak = hasher.finalize();
    let output_u8: Vec<u8> = keccak
        .iter()
        .flat_map(|&value| value.to_le_bytes().to_vec())
        .collect();
    output_u8
}

fn keccak256check(input: &Vec<u8>, output: &Vec<u8>) {
    let result = keccak256(&input);
    for i in 0..output.len() {
        unsafe { require(result[i] == output[i]) };
    }
    // fortest
    //unsafe {require(1 == 2);}
}

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn zkmain() -> i64 {
    let byte1_output : Vec<u8> = [
        21, 191, 54, 255, 99, 225, 69, 172, 52, 26, 134, 0, 126, 137, 21, 92, 243, 18, 222, 79, 162, 167, 211, 173, 63, 188, 75, 120, 1, 3, 35, 72,
    ].to_vec();
    keccak256check(&vec![197], &byte1_output);
    /*
    // empty input
    let emtpy_standard_output: Vec<u8> = [
        197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83,
        202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112,
    ]
    .to_vec();

    keccak256check(&vec![], &emtpy_standard_output);
    */

    /*
    // 1-byte input
    let byte1_output : Vec<u8> = [
        21, 191, 54, 255, 99, 225, 69, 172, 52, 26, 134, 0, 126, 137, 21, 92, 243, 18, 222, 79, 162, 167, 211, 173, 63, 188, 75, 120, 1, 3, 35, 72,
    ].to_vec();
    keccak256check(&vec![197], &byte1_output);

    // short input
    let short_standard_output: Vec<u8> = [
        172, 132, 33, 155, 248, 181, 178, 245, 199, 105, 157, 164, 188, 53, 193, 25, 7, 35, 159,
        188, 30, 123, 91, 143, 30, 100, 188, 128, 172, 248, 137, 202,
    ]
    .to_vec();
    // 整8个U8, 也就是整64个bit
    let input: Vec<u8> = [102, 111, 111, 98, 97, 114, 97, 97].to_vec();
    // 由于wasm的内存是以字节为单位的，所以这里需要将u64转换为u8
    keccak256check(&input, &short_standard_output);

    // long input
    let long_standard_output = [
        60, 227, 142, 8, 143, 135, 108, 85, 13, 254, 190, 58, 30, 106, 153, 194, 188, 6, 208, 49,
        16, 102, 150, 120, 100, 130, 224, 177, 64, 98, 53, 252,
    ]
    .to_vec();
    let input: Vec<u8> = [
        65, 108, 105, 99, 101, 32, 119, 97, 115, 32, 98, 101, 103, 105, 110, 110, 105, 110, 103,
        32, 116, 111, 32, 103, 101, 116, 32, 118, 101, 114, 121, 32, 116, 105, 114, 101, 100, 32,
        111, 102, 32, 115, 105, 116, 116, 105, 110, 103, 32, 98, 121, 32, 104, 101, 114, 32, 115,
        105, 115, 116, 101, 114, 32, 111, 110, 32, 116, 104, 101, 32, 98, 97, 110, 107, 44, 32, 97,
        110, 100, 32, 111, 102, 32, 104, 97, 118, 105, 110, 103, 32, 110, 111, 116, 104, 105, 110,
        103, 32, 116, 111, 32, 100, 111, 58, 32, 111, 110, 99, 101, 32, 111, 114, 32, 116, 119,
        105, 99, 101, 32, 115, 104, 101, 32, 104, 97, 100, 32, 112, 101, 101, 112, 101, 100, 32,
        105, 110, 116, 111, 32, 116, 104, 101, 32, 98, 111, 111, 107, 32, 104, 101, 114, 32, 115,
        105, 115, 116, 101, 114, 32, 119, 97, 115, 32, 114, 101, 97, 100, 105, 110, 103, 44, 32,
        98, 117, 116, 32, 105, 116, 32, 104, 97, 100, 32, 110, 111, 32, 112, 105, 99, 116, 117,
        114, 101, 115, 32, 111, 114, 32, 99, 111, 110, 118, 101, 114, 115, 97, 116, 105, 111, 110,
        115, 32, 105, 110, 32, 105, 116, 44, 32, 97, 110, 100, 32, 119, 104, 97, 116, 32, 105, 115,
        32, 116, 104, 101, 32, 117, 115, 101, 32, 111, 102, 32, 97, 32, 98, 111, 111, 107, 44, 32,
        116, 104, 111, 117, 103, 104, 116, 32, 65, 108, 105, 99, 101, 32, 119, 105, 116, 104, 111,
        117, 116, 32, 112, 105, 99, 116, 117, 114, 101, 115, 32, 111, 114, 32, 99, 111, 110, 118,
        101, 114, 115, 97, 116, 105, 111, 110, 115, 63,
    ]
    .to_vec();
    // zkwasm-host-keccak256 实现的keccak256 必须是U8的倍数, 这里input不满足,过不比较了
    keccak256check(&input, &long_standard_output);

    */
    0
}
/*
#[test]
fn test_empty_input() {
    let output = [
        197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83,
        202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112,
    ];
    assert_eq!(keccak256(&[]), output);
}

#[test]
fn test_short_input() {
    let output = [
        56, 209, 138, 203, 103, 210, 92, 139, 185, 148, 39, 100, 182, 47, 24, 225, 112, 84, 246,
        106, 129, 123, 212, 41, 84, 35, 173, 249, 237, 152, 135, 62,
    ];
    assert_eq!(keccak256(&[102, 111, 111, 98, 97, 114]), output);
}

#[test]
fn test_long_input() {
    let input = [
        65, 108, 105, 99, 101, 32, 119, 97, 115, 32, 98, 101, 103, 105, 110, 110, 105, 110, 103,
        32, 116, 111, 32, 103, 101, 116, 32, 118, 101, 114, 121, 32, 116, 105, 114, 101, 100, 32,
        111, 102, 32, 115, 105, 116, 116, 105, 110, 103, 32, 98, 121, 32, 104, 101, 114, 32, 115,
        105, 115, 116, 101, 114, 32, 111, 110, 32, 116, 104, 101, 32, 98, 97, 110, 107, 44, 32, 97,
        110, 100, 32, 111, 102, 32, 104, 97, 118, 105, 110, 103, 32, 110, 111, 116, 104, 105, 110,
        103, 32, 116, 111, 32, 100, 111, 58, 32, 111, 110, 99, 101, 32, 111, 114, 32, 116, 119,
        105, 99, 101, 32, 115, 104, 101, 32, 104, 97, 100, 32, 112, 101, 101, 112, 101, 100, 32,
        105, 110, 116, 111, 32, 116, 104, 101, 32, 98, 111, 111, 107, 32, 104, 101, 114, 32, 115,
        105, 115, 116, 101, 114, 32, 119, 97, 115, 32, 114, 101, 97, 100, 105, 110, 103, 44, 32,
        98, 117, 116, 32, 105, 116, 32, 104, 97, 100, 32, 110, 111, 32, 112, 105, 99, 116, 117,
        114, 101, 115, 32, 111, 114, 32, 99, 111, 110, 118, 101, 114, 115, 97, 116, 105, 111, 110,
        115, 32, 105, 110, 32, 105, 116, 44, 32, 97, 110, 100, 32, 119, 104, 97, 116, 32, 105, 115,
        32, 116, 104, 101, 32, 117, 115, 101, 32, 111, 102, 32, 97, 32, 98, 111, 111, 107, 44, 32,
        116, 104, 111, 117, 103, 104, 116, 32, 65, 108, 105, 99, 101, 32, 119, 105, 116, 104, 111,
        117, 116, 32, 112, 105, 99, 116, 117, 114, 101, 115, 32, 111, 114, 32, 99, 111, 110, 118,
        101, 114, 115, 97, 116, 105, 111, 110, 115, 63,
    ];
    let output = [
        60, 227, 142, 8, 143, 135, 108, 85, 13, 254, 190, 58, 30, 106, 153, 194, 188, 6, 208, 49,
        16, 102, 150, 120, 100, 130, 224, 177, 64, 98, 53, 252,
    ];
    assert_eq!(keccak256(&input), output);
}
*/
