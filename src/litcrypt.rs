//! # LitCrypt
//! The name is an abbreviation of ‘Literal Encryption’ – a Rust compiler plugin to encrypt
//! text literals using the [XOR cipher](https://en.wikipedia.org/wiki/XOR_cipher).
//!
//! LitCrypt let’s you hide your static string literal in the binary from naughty eyes and protect
//! your app from illegal cracking activity.
//!
//! LitCrypt works by encrypting string literals during compile time. An encrypted string remains
//! encrypted both on disk and in memory during runtime. It is decypted only when used.
//!
//! ## Usage
//! In `Cargo.toml`, add:
//!
//! ```toml
//! [dependencies]
//! litcrypt = "0.2"
//! ```
//!
//! # Example
//!
//! ```rust
//! #[macro_use]
//! extern crate litcrypt;
//!
//! use_litcrypt!("MY-SECRET-SPELL");
//!
//! fn main(){
//!     println!("his name is: {}", lc!("Voldemort"));
//! }
//! ```
//!
//! The [`use_litcrypt!`] macro must be called first, for initialization. Its parameter is the
//! secret key that is used to encrypt all [`lc!`]-wrapped string literal(s).
//! This key is also encrypted and will not visible in a static analyzer.
//!
//! Only after that can you use the [`lc!`] macro.
//!
//! You can also override the key using an environment variable `LITCRYPT_ENCRYPT_KEY` e.g:
//! ```bash
//! ❯ export LITCRYPT_ENCRYPT_KEY="myverysuperdupermegaultrasecretkey"
//! ```
//!
//! LitCrypt will statically encrypt every string encapsulated in an `lc!` macro.
//!
//! Check the output binary using the `strings` command, e.g:
//!
//! ```bash
//! ❯ strings target/debug/my_valuable_app | grep Voldemort
//! ```
//!
//! If the output is blank then the resp. strings in your app are safe from a static analyzer tool
//! like a hex editor.
//!
//! For an example see the `./examples` directory:
//!
//! ```bash
//! ❯ cargo run --example simple
//! ```
extern crate blake3;
extern crate proc_macro;
extern crate proc_macro2;
extern crate quote;
extern crate rand;

#[cfg(test)]
#[macro_use(expect)]
extern crate expectest;
use blake3::Hash;
use proc_macro::{TokenStream, TokenTree};
use proc_macro2::Literal;
use quote::quote;
use rand::{rngs::OsRng, Rng, RngCore, SeedableRng};
use std::{env, hash::{DefaultHasher, Hasher}};

mod xor;
lazy_static::lazy_static! {
    static ref RAND_SPELL: [u8; 64] = {
        let mut key = [0u8; 64];
        OsRng.fill_bytes(&mut key);
        key
    };
}

#[inline(always)]
fn get_magic_spell() -> Vec<u8> {
    match env::var("LITCRYPT_ENCRYPT_KEY") {
        Ok(key) => {
        let mut st = rand::rngs::StdRng::from_seed({const OUT_LEN: usize = 32; let mut h = DefaultHasher::new(); h.write(key.as_bytes());h.write(&"RUSSIA".as_bytes());let x = [255u8;8];let c = [200u8;8];let z = [0u8;8]; let bhash = Hash::from_slice(&[h.finish().to_be_bytes(),z,x,c].concat()); bhash.unwrap().into()});
        let mut fk = DefaultHasher::new();
        let ii8: i8 = {st.r#gen()};
        fk.write_i8(ii8);
        let ii64b= {st.r#gen::<i64>().to_be_bytes()};
        fk.write(&ii64b);
        fk.write(key.as_bytes());
        let ii128: i128 = {st.r#gen()};
        fk.write_i128(ii128);
        fk.finish().to_be_bytes().to_vec()
        },
        Err(_) => {
            // `lc!` will call this function multi times
            // we must provide exact same result for each invocation
            // so use static lazy field for cache
            RAND_SPELL.to_vec()
        }
    }
}

/// Sets the encryption key used for encrypting subsequence strings wrapped in a [`lc!`] macro.
///
/// This key is also encrypted an  will not visible in a static analyzer.
#[proc_macro]
pub fn use_litcrypt(_tokens: TokenStream) -> TokenStream {
    let magic_spell = get_magic_spell();

    let encdec_func = quote! {
        pub mod litcrypt_internal {
            // This XOR code taken from https://github.com/zummenix/xor-rs
            /// Returns result of a XOR operation applied to a `source` byte sequence.
            ///
            /// `key` will be an infinitely repeating byte sequence.
            pub fn xor(source: &[u8], key: &[u8]) -> Vec<u8> {
                match key.len() {
                    0 => source.into(),
                    1 => xor_with_byte(source, key[0]),
                    _ => {
                        let key_iter = InfiniteByteIterator::new(key);
                        source.iter().zip(key_iter).map(|(&a, b)| a ^ b).collect()
                    }
                }
            }

            /// Returns result of a XOR operation applied to a `source` byte sequence.
            ///
            /// `byte` will be an infinitely repeating byte sequence.
            pub fn xor_with_byte(source: &[u8], byte: u8) -> Vec<u8> {
                source.iter().map(|&a| a ^ byte).collect()
            }

            struct InfiniteByteIterator<'a> {
                bytes: &'a [u8],
                index: usize,
            }

            impl<'a> InfiniteByteIterator<'a> {
                pub fn new(bytes: &'a [u8]) -> InfiniteByteIterator<'a> {
                    InfiniteByteIterator {
                        bytes: bytes,
                        index: 0,
                    }
                }
            }

            impl<'a> Iterator for InfiniteByteIterator<'a> {
                type Item = u8;
                fn next(&mut self) -> Option<u8> {
                    let byte = self.bytes[self.index];
                    self.index = next_index(self.index, self.bytes.len());
                    Some(byte)
                }
            }

            fn next_index(index: usize, count: usize) -> usize {
                if index + 1 < count {
                    index + 1
                } else {
                    0
                }
            }

            pub fn decrypt_bytes(encrypted: &[u8], encrypt_key: &[u8]) -> String {
                let decrypted = xor(&encrypted[..], &encrypt_key);
                String::from_utf8(decrypted).unwrap()
            }
        }
    };
    let result = {
        let mut st = rand::rngs::StdRng::from_seed({const OUT_LEN: usize = 32; let mut h = DefaultHasher::new(); h.write("5fdd3d3610a08eaf2c2ecc69c76e8fdcfb64dbdbbbc772441f98c58f40a57ef39f73e9ce04b0a266e491230cfeff9347c0e7f97434fdced3b663d43375c9e2d09a86833bc6bd8ccc2f4fdd5af6de8c84af7d97184f5641a44526cb54d23c779bc465b169ab4fec59db53843177b28c".as_bytes());h.write(&"RUSSIA".as_bytes());let x = [255u8;8];let c = [200u8;8];let z = [0u8;8]; let bhash = Hash::from_slice(&[h.finish().to_be_bytes(),z,x,c].concat()); bhash.unwrap().into()});
        let ii8 = {st.r#gen()};
        let ii128={st.r#gen()};
        let scr = {let mut key = DefaultHasher::new(); key.write_i8(ii8); key.write(b"a6769e5b68e790a70ab305f1dc24e18c9573350748741a5454b5ac1a60a492f5bdb812dd7f"); key.write_i128(ii128); &key.finish().to_be_bytes()};
        let ekey = xor::xor(&magic_spell, scr);
        let ekey = Literal::byte_string(&ekey);
        quote! {
            static LITCRYPT_ENCRYPT_KEY: &'static [u8] = #ekey;
            #encdec_func
        }
    };
    result.into()
}

/// Encrypts the resp. string with the key set before, via calling [`use_litcrypt!`].
#[proc_macro]
pub fn lc(tokens: TokenStream) -> TokenStream {
    let mut something = String::from("");
    for tok in tokens {
        something = match tok {
            TokenTree::Literal(lit) => lit.to_string(),
            _ => "<unknown>".to_owned(),
        }
    }
    something = String::from(&something[1..something.len() - 1]);

    encrypt_string(something)
}

/// Encrypts an environment variable at compile time with the key set before, via calling [`use_litcrypt!`].
#[proc_macro]
pub fn lc_env(tokens: TokenStream) -> TokenStream {
    let mut var_name = String::from("");

    for tok in tokens {
        var_name = match tok {
            TokenTree::Literal(lit) => lit.to_string(),
            _ => "<unknown>".to_owned(),
        }
    }

    var_name = String::from(&var_name[1..var_name.len() - 1]);

    encrypt_string(env::var(var_name).unwrap_or(String::from("unknown")))
}

fn encrypt_string(something: String) -> TokenStream {
    let magic_spell = get_magic_spell();
    let mut st = rand::rngs::StdRng::from_seed({const OUT_LEN: usize = 32; let mut h = DefaultHasher::new(); h.write("15214de0f3ac6f2d642ceeda9b3209cf56d01e09c37f76903b3ece6460330cfe39e10256a03b5dfae8bd687a26fc652ed6b581f1b0e9d8c2c388a11be45031943740fb1728a53c492e51bc09d5b3311feb0662cc58b8df03674334e6a5e561a8e93abae261a826cfabd6faa7475099".as_bytes());h.write(&"RUSSIA".as_bytes());let x = [255u8;8];let c = [200u8;8];let z = [0u8;8]; let bhash = Hash::from_slice(&[h.finish().to_be_bytes(),z,x,c].concat()); bhash.unwrap().into()});
    let ii8 = st.r#gen();
    let ii128 = st.r#gen();
    let scr = {let mut key = DefaultHasher::new(); key.write_i8(ii8);
         key.write(b"61b57a14a1ed38162fd45e07fcbca3d5eb019de2e72929c94533b8239af129634ec89ad75d7976");
         key.write_i128(ii128); &key.finish().to_be_bytes()};
    let encrypt_key = xor::xor(&magic_spell, scr);
    let encrypted = xor::xor(something.as_bytes(), &encrypt_key);
    let encrypted = Literal::byte_string(&encrypted);

    let result = quote! {
        crate::litcrypt_internal::decrypt_bytes(#encrypted, crate::LITCRYPT_ENCRYPT_KEY)
    };

    result.into()
}