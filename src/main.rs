use std::env;
use std::path::{Path};
use std::fs::{File, OpenOptions};
use std::io:: {Write, Read, Seek, SeekFrom, Cursor};

use aes::Aes128;
use cbc::{Decryptor, cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit}};

type Aes128CbcDec = Decryptor<Aes128>;

static KEYS: &[(&str, &str)] = &[
    ("T-NT14M", "95d01e0bae861a05695bc8a6edb2ea835a09accd"),
];

struct Section {
    index: u32,
    offset: u32,
    size: u32,
    name: String,
}

fn decrypt_aes(encrypted_data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = encrypted_data.to_vec();
    let decryptor = Aes128CbcDec::new(key.into(), iv.into());
    let decrypted = decryptor.decrypt_padded_mut::<Pkcs7>(&mut data)
        .map_err(|e| format!("!!Decryption error!!: {:?}", e))?;
    
    Ok(decrypted.to_vec())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Legacy MSD extractor tool");
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <filename> <output_folder>", args[0]);
        std::process::exit(1);
    }

    let filename = &args[1];
    let mut file = File::open(filename)?;

    let output_folder = &args[2];

    let mut magic = [0u8; 6];
    file.read_exact(&mut magic)?; 
    if &magic != b"MSDU10" {
        eprintln!("Error: Not a valid MSD file!");
        std::process::exit(1);
    }
    
    let mut section_count_bytes = [0u8; 4];
    file.read_exact(&mut section_count_bytes)?;
    let section_count = u32::from_le_bytes(section_count_bytes);
    
    println!("Number of sections: {}", section_count);
    println!();

    let mut sections: Vec<Section> = Vec::new();

    //parse sections
    for _i in 0..section_count {
        // 4 bytes index
        let mut index_bytes = [0u8; 4];
        file.read_exact(&mut index_bytes)?;
        let index = u32::from_le_bytes(index_bytes);
        
        // 4 bytes offset
        let mut offset_bytes = [0u8; 4];
        file.read_exact(&mut offset_bytes)?;
        let offset = u32::from_le_bytes(offset_bytes);
        
        // 4 bytes size
        let mut size_bytes = [0u8; 4];
        file.read_exact(&mut size_bytes)?;
        let size = u32::from_le_bytes(size_bytes);

        println!("Section {}: offset: {}, size: {}", index, offset, size);
        sections.push(Section { index, offset, size , name: "aaa".to_string() });
    }

    //read TOC entry
    let mut toc_entry_bytes = [0u8; 4];
    file.read_exact(&mut toc_entry_bytes)?;
    let toc_entry = u32::from_le_bytes(toc_entry_bytes);
    assert!(toc_entry == 0, "invalid TOC entry!");

    // 4 bytes index
    let mut toc_index_bytes = [0u8; 4];
    file.read_exact(&mut toc_index_bytes)?;
    let _toc_index = u32::from_le_bytes(toc_index_bytes);

    // 4 bytes offset
    let mut toc_offset_bytes = [0u8; 4];
    file.read_exact(&mut toc_offset_bytes)?;
    let toc_offset = u32::from_le_bytes(toc_offset_bytes);
        
    // 4 bytes size
    let mut toc_size_bytes = [0u8; 4];
    file.read_exact(&mut toc_size_bytes)?;
    let toc_size = u32::from_le_bytes(toc_size_bytes);
    println!("TOC Section: offset: {}, size: {}", toc_offset, toc_size);

    println!();

    //Read firmware name
    let mut name_size_byte = [0u8; 1];
    file.read_exact(&mut name_size_byte)?;
    let name_size = u8::from_le_bytes(name_size_byte);

    let mut name_bytes = vec![0u8; name_size as usize];
    file.read_exact(&mut name_bytes)?;
    let name = String::from_utf8(name_bytes)?;
    println!("Firmware: {}", name);

    let mut passphrase: Option<&str> = None;
    let passphrase_bytes;

    //find passphrase
    for (prefix, value) in KEYS {
        if name.starts_with(prefix) {
            passphrase = Some(value);
            break;
        }
    }
    if let Some(p) = passphrase {
        println!("Passphrase: {}", p);
        passphrase_bytes = hex::decode(p)?;
    } else {
        println!("Sorry, this firmware is not supported!");
        std::process::exit(1);
    }

    println!();
    println!("Parsing TOC...");

    //read and decrypt TOC
    file.seek(SeekFrom::Start(toc_offset as u64))?;
    let mut encrypted_toc = vec![0u8; toc_size as usize];
    file.read_exact(&mut encrypted_toc)?;

    assert!(String::from_utf8((&encrypted_toc[0..8]).to_vec())? == "Salted__", "invalid TOC!");
    let salt = &encrypted_toc[8..16];

    let key: Vec<u8> = [&passphrase_bytes, salt].concat();
    let key_md5 = md5::compute(&key);

    let mut iv = Vec::new();
    iv.extend_from_slice(&key_md5.0);
    iv.extend_from_slice(&passphrase_bytes);
    iv.extend_from_slice(&salt);
    let iv_md5 = md5::compute(&iv);

    let toc = decrypt_aes(&encrypted_toc[16..], &key_md5, &iv_md5)?;

    let mut toc_reader = Cursor::new(toc);

    toc_reader.seek(SeekFrom::Current(128))?; // probably signature
    let mut n = 1;

    while (toc_reader.position() as usize) < toc_reader.get_ref().len() {
        if n != 1 { //isnt on first segment
            toc_reader.seek(SeekFrom::Current(4))?; //some magic?
        }

        let mut segment_length_bytes = [0u8; 4];
        toc_reader.read_exact(&mut segment_length_bytes)?;
        let segment_length = u32::from_be_bytes(segment_length_bytes);

        let mut segment_size_bytes = [0u8; 4];
        toc_reader.read_exact(&mut segment_size_bytes)?;
        let segment_size = u32::from_be_bytes(segment_size_bytes);

        if segment_size != 0 {
            assert!(segment_size == sections[n - 1].size, "size in TOC does not match size from header!");

            toc_reader.seek(SeekFrom::Current(26))?; //unknown now

            let mut name_length_byte = [0u8; 1];
            toc_reader.read_exact(&mut name_length_byte)?;
            let name_length = u8::from_be_bytes(name_length_byte);

            let mut name_bytes = vec![0u8; name_length as usize];
            toc_reader.read_exact(&mut name_bytes)?;
            let name = String::from_utf8(name_bytes)?;

            //println!("Segment: name='{}', length={}, size={}", name, segment_length, segment_size);
            // apply respective names to sections
            if n != 1 && sections[n-2].name == name{ //second section with the same name is some sort of signature
                sections[n-1].name = name + "_sign";
            } else {
                sections[n-1].name = name;
            }

            toc_reader.seek(SeekFrom::Current((segment_length - 31 - name_length as u32).into()))?;

            n = n + 1;
        } else {
            break; //0 sized segment is end
        }
    }

    println!();

    for (_i, section) in sections.iter().enumerate() {
        println!("Extracting section {}: {}...", section.index, section.name);

        let mut out_data: Vec<u8>;

        if section.name.ends_with("_sign") {
            //unknown format
            file.seek(SeekFrom::Start(section.offset as u64))?;
            out_data = vec![0u8; section.size as usize];
            file.read_exact(&mut out_data)?;
            
        } else { 
            file.seek(SeekFrom::Start(section.offset as u64 + 136))?; // skip signature
            let mut encrypted_data = vec![0u8; section.size as usize - 136];
            file.read_exact(&mut encrypted_data)?;

            //decrypt
            assert!(String::from_utf8((&encrypted_data[0..8]).to_vec())? == "Salted__", "invalid file data!");
            let salt = &encrypted_data[8..16];

            let key: Vec<u8> = [&passphrase_bytes, salt].concat();
            let key_md5 = md5::compute(&key);

            let mut iv = Vec::new();
            iv.extend_from_slice(&key_md5.0);
            iv.extend_from_slice(&passphrase_bytes);
            iv.extend_from_slice(&salt);
            let iv_md5 = md5::compute(&iv);

            out_data = decrypt_aes(&encrypted_data[16..], &key_md5, &iv_md5)?;
        }

        std::fs::create_dir_all(output_folder)?;
        let output_path = Path::new(output_folder).join(&section.name);
        let mut out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&output_path)?;
        out_file.write_all(&out_data)?;

    }

    println!();
    println!("Done! Saved extracted files to '{}'", output_folder);

    Ok(())
}