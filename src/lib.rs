use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::Path;

use byteorder::{LittleEndian, ReadBytesExt};
use encoding_rs::GBK;

mod errors;
use errors::Error;
const INDEX_LEN: u64 = 7;

#[derive(Debug)]
pub struct IPDB {
    file: File,
    header: Header,

    position: u64,
}

#[derive(Debug, std::cmp::PartialEq)]
pub struct Record {
    pub ip: Ipv4Addr,
    pub country: String,
    pub area: String,
}

#[derive(Debug)]
struct Header {
    start: u64,
    end: u64,
}

impl Header {
    fn decode(mut bytes: &[u8]) -> Result<Self, Error> {
        let header = Self {
            start: bytes.read_u32::<LittleEndian>()? as u64,
            end: bytes.read_u32::<LittleEndian>()? as u64,
        };

        Ok(header)
    }
}

fn get_middle_offset(start: u64, end: u64) -> u64 {
    let records = ((end - start) / INDEX_LEN) >> 1;
    start + records * INDEX_LEN
}

fn array3u8tou32(data: &[u8]) -> u32 {
    let mut i = data[0] as u32 & 0xff;
    i |= (data[1] as u32) << 8 & 0xff00;
    i |= (data[2] as u32) << 16 & 0xff0000;
    i
}

enum Mode {
    RediectMode1,
    RediectMode2,
    Other,
}

impl Mode {
    fn from(mode: u8) -> Self {
        match mode {
            1 => Self::RediectMode1,
            2 => Self::RediectMode2,
            _ => Self::Other,
        }
    }
}

use std::net::Ipv4Addr;

fn convert_ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    let array = ip.octets();
    let mut result = array[0] as u32;
    result |= ((array[1] as u32) << 8) & 0xff00;
    result |= ((array[2] as u32) << 16) & 0xff0000;
    result |= ((array[3] as u32) << 24) & 0xff000000;
    result
}

impl IPDB {
    pub fn new(path: &str) -> Self {
        let p = Path::new(path);
        let display = p.display();

        let mut file = match File::open(&p) {
            Err(why) => panic!("couldn't open {}: {}", display, why),
            Ok(file) => file,
        };

        let mut buf = [0; 8];
        let header = match file.read(&mut buf) {
            Err(err) => panic!("could't read {}: {}", display, err),
            Ok(_) => Header::decode(&mut buf).unwrap(),
        };

        IPDB {
            file: file,
            header: header,
            position: 0,
        }
    }

    pub fn find(&mut self, ip: Ipv4Addr) -> Result<Record, Error> {
        let offset = self.search_index(ip)?;
        self.get_content(offset)
    }

    fn search_index(&mut self, ip: Ipv4Addr) -> Result<u64, Error> {
        let ip_num = convert_ipv4_to_u32(ip);
        let (mut start, mut end) = (self.header.start, self.header.end);
        loop {
            let mid = get_middle_offset(start, end);
            self.file.seek(std::io::SeekFrom::Start(mid))?;

            let mut buf = [0; INDEX_LEN as usize];
            self.file.read(&mut buf)?;

            let mid_ip = (&buf[0..4]).read_u32::<LittleEndian>()?;

            if ip_num == mid_ip {
                return Ok(array3u8tou32(&buf[4..7]) as u64);
            }

            if end - start == INDEX_LEN {
                return Err(Error::from("couldn't find ip"));
            }

            if ip_num > mid_ip {
                start = mid;
            } else {
                end = mid;
            }
        }
    }

    fn read_ip(&mut self, offset: u64) -> Result<Ipv4Addr, Error> {
        self.file.seek(io::SeekFrom::Start(offset))?;

        let mut buf = [0; 4];
        self.file.read(&mut buf)?;

        Ok(Ipv4Addr::from(buf))
    }

    fn read_mode(&mut self, offset: u64) -> Result<Mode, Error> {
        self.file.seek(io::SeekFrom::Start(offset))?;

        let mut buf = [0; 1];
        self.file.read(&mut buf)?;

        Ok(Mode::from(buf[0]))
    }

    fn read_area(&mut self, offset: u64) -> Result<Vec<u8>, Error> {
        match self.read_mode(offset)? {
            Mode::RediectMode2 | Mode::RediectMode1 => {
                let area_offset = self.read_u24()?;
                if area_offset == 0 {
                    Err(Error::from(format!("Wrong content, in {}", offset + 1)))
                } else {
                    self.read_string(area_offset as u64)
                }
            }
            Mode::Other => self.read_string(offset),
        }
    }

    fn read_u24(&mut self) -> Result<u32, Error> {
        let mut buf = [0; 3];
        self.file.read(&mut buf)?;
        Ok(array3u8tou32(&buf))
    }

    fn read_string(&mut self, offset: u64) -> Result<Vec<u8>, Error> {
        self.file.seek(io::SeekFrom::Start(offset))?;
        let mut result = Vec::new();
        let mut buf = [0; 1];
        loop {
            self.file.read(&mut buf)?;
            if buf[0] == 0 {
                break;
            }
            result.push(buf[0]);
        }

        Ok(result)
    }

    fn get_content(&mut self, offset: u64) -> Result<Record, Error> {
        let mode = self.read_mode(offset + 4)?;
        let (country, area) = match mode {
            Mode::RediectMode1 => {
                let country_offset = self.read_u24()? as u64;
                let mode = self.read_mode(country_offset)?;
                let (country, area_offset) = match mode {
                    Mode::RediectMode2 => {
                        let c = self.read_u24()? as u64;
                        let country = self.read_string(c)?;
                        (country, country_offset + 4)
                    }
                    _ => {
                        let country = self.read_string(country_offset)?;
                        let country_len = country.len();
                        (country, country_offset + country_len as u64 + 1)
                    }
                };

                let area = self.read_area(area_offset)?;
                (country, area)
            }

            Mode::RediectMode2 => {
                let country_offset = self.read_u24()?;
                let country = self.read_string(country_offset as u64)?;
                let area = self.read_area(offset + 5 + country.len() as u64)?;
                (country, area)
            }
            Mode::Other => {
                let country = self.read_string(offset + 4)?;
                let area = self.read_area(offset + 5 + country.len() as u64)?;
                (country, area)
            }
        };

        let (country_str, _, _) = GBK.decode(&country);
        let (area_str, _, _) = GBK.decode(&area);

        Ok(Record {
            ip: self.read_ip(offset)?,
            country: country_str.to_string(),
            area: area_str.to_string(),
        })
    }

    pub fn iter_init(&mut self) -> Result<(), Error> {
        if self.position == 0 {
            self.position = self.header.start;
        }

        let position = self.file.stream_position().unwrap();
        if position != self.position {
            self.file.seek(io::SeekFrom::Start(self.position))?;
        }

        Ok(())
    }

    pub fn iter_next(&mut self) -> Result<Record, Error> {
        let position = self.file.stream_position().unwrap();
        if position != self.position {
            self.file.seek(io::SeekFrom::Start(self.position))?;
        }
        let mut buf = [0; INDEX_LEN as usize];
        let n = self.file.read(&mut buf)?;
        self.position += n as u64;

        self.get_content(array3u8tou32(&buf[4..]) as u64)
    }

    pub fn iter_has_next(&mut self) -> bool {
        if self.position == self.header.end + INDEX_LEN {
            false
        } else {
            true
        }
    }
}

#[test]
fn test_iter() {
    let mut db = IPDB::new("./data/qqwry.dat");
    let mut count = 0;
    db.iter_init().unwrap();
    while db.iter_has_next() {
        db.iter_next().unwrap();
        count += 1;
    }

    assert_eq!(
        count,
        (db.header.end + INDEX_LEN - db.header.start) / INDEX_LEN
    );
}

#[test]
fn test_find() {
    let mut db = IPDB::new("./data/qqwry.dat");
    let result = Record {
        ip: Ipv4Addr::new(8, 8, 8, 8),
        country: "美国".to_string(),
        area: "加利福尼亚州圣克拉拉县山景市谷歌公司DNS服务器".to_string(),
    };

    let record = db.find(result.ip).unwrap();
    assert_eq!(record, result);
}
