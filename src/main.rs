use std::path::{Path};
use std::fs::{File, OpenOptions};
use std::io:: {self, Write, Read, Seek, SeekFrom, Cursor};

use clap::Parser;
use aes::Aes128;
use cbc::{Decryptor, cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit}};

type Aes128CbcDec = Decryptor<Aes128>;

#[derive(Parser, Debug)]
struct Args {
    /// Keep signature files
    #[arg(short = 's')]
    keep_sign: bool,

    input_file: String,
    output_folder: String,
}

static KEYS: &[(&str, &str)] = &[
    ("T-NT14M", "95d01e0bae861a05695bc8a6edb2ea835a09accd"),
];

struct Section {
    index: u32,
    offset: u32,
    size: u32,
    name: String,
}

fn read_exact<R: Read>(reader: &mut R, size: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

fn decrypt_aes_salted(encrypted_data: &[u8], passphrase_bytes: &Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = encrypted_data.to_vec();

    assert!(String::from_utf8(data[0..8].to_vec())? == "Salted__", "invalid encrypted data!");
    let salt = &data[8..16];

    //key = md5 of (passphrase + salt)
    let mut key = Vec::new();
    key.extend_from_slice(&passphrase_bytes);
    key.extend_from_slice(&salt);
    let key_md5 = md5::compute(&key);

    //iv = md5 of (md5 of key + passphrase + salt)
    let mut iv = Vec::new();
    iv.extend_from_slice(&key_md5.0);
    iv.extend_from_slice(&passphrase_bytes);
    iv.extend_from_slice(&salt);
    let iv_md5 = md5::compute(&iv);

    let decryptor = Aes128CbcDec::new((&key_md5.0).into(), (&iv_md5.0).into());
    let decrypted = decryptor.decrypt_padded_mut::<Pkcs7>(&mut data[16..])
        .map_err(|e| format!("Decryption error!!: {:?}", e))?;
    
    Ok(decrypted.to_vec())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Legacy MSD extractor tool");
    let args = Args::parse();
    println!();

    let filename = args.input_file;
    println!("Input file: {}", filename);
    let mut file = File::open(filename)?;

    let output_folder = args.output_folder;
    println!("Output folder: {}", output_folder);
    println!();

    let keep_sign = args.keep_sign;

    //magic
    let magic = read_exact(&mut file, 6)?;
    if &magic != b"MSDU10" {
        eprintln!("Error: Not a valid legacy MSD file!");
        std::process::exit(1);
    }
    
    //section count
    let section_count_bytes = read_exact(&mut file, 4)?;
    let section_count = u32::from_le_bytes(section_count_bytes.try_into().unwrap());
    println!("Number of sections: {}", section_count);

    let mut sections: Vec<Section> = Vec::new();

    //parse sections
    for _i in 0..section_count {
        // 4 bytes index
        let index_bytes = read_exact(&mut file, 4)?;
        let index = u32::from_le_bytes(index_bytes.try_into().unwrap());
        
        // 4 bytes offset
        let offset_bytes = read_exact(&mut file, 4)?;
        let offset = u32::from_le_bytes(offset_bytes.try_into().unwrap());
        
        // 4 bytes size
        let size_bytes = read_exact(&mut file, 4)?;
        let size = u32::from_le_bytes(size_bytes.try_into().unwrap());

        println!("Section {}: offset: {}, size: {}", index, offset, size);
        sections.push(Section { index, offset, size , name: "".to_string() });
    }

    //read TOC entry
    let toc_entry_bytes = read_exact(&mut file, 4)?;
    let toc_entry = u32::from_le_bytes(toc_entry_bytes.try_into().unwrap());
    assert!(toc_entry == 0, "invalid TOC entry!");

    // 4 bytes index?
    let _toc_index_bytes = read_exact(&mut file, 4)?;

    // 4 bytes offset
    let toc_offset_bytes = read_exact(&mut file, 4)?;
    let toc_offset = u32::from_le_bytes(toc_offset_bytes.try_into().unwrap());
        
    // 4 bytes size
    let toc_size_bytes = read_exact(&mut file, 4)?;
    let toc_size = u32::from_le_bytes(toc_size_bytes.try_into().unwrap());

    println!("TOC Section: offset: {}, size: {}", toc_offset, toc_size);
    println!();

    //Read firmware name
    let name_size_byte = read_exact(&mut file, 1)?;
    let name_size = u8::from_le_bytes(name_size_byte.try_into().unwrap());

    let name_bytes = read_exact(&mut file, name_size as usize)?;
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
    let encrypted_toc = read_exact(&mut file, toc_size as usize)?;
    let toc = decrypt_aes_salted(&encrypted_toc, &passphrase_bytes)?;

    let mut toc_reader = Cursor::new(toc);

    toc_reader.seek(SeekFrom::Current(128))?; // probably signature
    let mut n = 0;

    while (toc_reader.position() as usize) < toc_reader.get_ref().len() {
        if n != 0 { //isnt on first segment
            toc_reader.seek(SeekFrom::Current(4))?; //some magic? seems to be 00 00 03 E8 always
        }

        let segment_length_bytes = read_exact(&mut toc_reader, 4)?;
        let segment_length = u32::from_be_bytes(segment_length_bytes.try_into().unwrap());

        let segment_size_bytes = read_exact(&mut toc_reader, 4)?;
        let segment_size = u32::from_be_bytes(segment_size_bytes.try_into().unwrap());

        if segment_size != 0 {
            assert!(segment_size == sections[n].size, "size in TOC does not match size from header!");

            toc_reader.seek(SeekFrom::Current(26))?; //unknown now

            let name_length_byte = read_exact(&mut toc_reader, 1)?;
            let name_length = u8::from_be_bytes(name_length_byte.try_into().unwrap());

            let name_bytes = read_exact(&mut toc_reader, name_length as usize)?;
            let name = String::from_utf8(name_bytes)?;

            //println!("Segment: name='{}', length={}, size={}", name, segment_length, segment_size);
            // apply respective names to sections
            if n != 0 && sections[n-1].name == name{ //second section with the same name is some sort of signature
                sections[n].name = name + "_sign";
            } else {
                sections[n].name = name;
            }

            toc_reader.seek(SeekFrom::Current((segment_length - name_length as u32 - 31).into()))?;

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
            //in raw format
            if keep_sign {
                file.seek(SeekFrom::Start(section.offset as u64))?;
                out_data = vec![0u8; section.size as usize];
                file.read_exact(&mut out_data)?;
            } else {
                println!("- Skipping signature file...");
                continue;
            }      
        } else { 
            file.seek(SeekFrom::Start(section.offset as u64 + 136))?; // skip signature
            let mut encrypted_data = vec![0u8; section.size as usize - 136];
            file.read_exact(&mut encrypted_data)?;
            out_data = decrypt_aes_salted(&encrypted_data, &passphrase_bytes)?;
        }

        std::fs::create_dir_all(&output_folder)?;
        let output_path = Path::new(&output_folder).join(&section.name);
        let mut out_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&output_path)?;
        out_file.write_all(&out_data)?;

        println!("- Saved file!");
    }

    println!();
    println!("Done! Saved extracted files to '{}'", output_folder);

    Ok(())
}