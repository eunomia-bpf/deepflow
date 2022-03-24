use super::consts::*;
use super::Header;

use crate::{
    common::{
        enums::{IpProtocol, PacketDirection},
        flow::L7Protocol,
        protocol_logs::{AppProtoLogsData, AppProtoLogsInfo, LogMessageType, MysqlInfo},
    },
    utils::bytes,
};

#[derive(Debug, Default)]
struct MysqlLog {
    pub info: MysqlInfo,

    l7_proto: L7Protocol,
    msg_type: LogMessageType,
}

impl MysqlLog {
    fn request_none() {}

    fn request_string(&mut self, payload: &[u8]) {
        if payload.len() > 2 && payload[0] == 0 && payload[1] == 1 {
            // MYSQL 8.0.26返回字符串前有0x0、0x1，MYSQL 8.0.21版本没有这个问题
            // https://gitlab.yunshan.net/platform/trident/-/merge_requests/2592#note_401425
            self.info.context = String::from_utf8_lossy(&payload[2..]).into_owned();
        } else {
            self.info.context = String::from_utf8_lossy(payload).into_owned();
        }
    }

    fn new() -> Self {
        MysqlLog::default()
    }

    fn reset_logs(&mut self) {
        self.info = MysqlInfo::default();
    }

    fn get_log_data_special_info(self, log_data: &mut AppProtoLogsData) {
        if (&self).msg_type == LogMessageType::Response
            && (&self).info.response_code == MYSQL_RESPONSE_CODE_ERR
        {
            log_data.base_info.head.code = (&self).info.error_code;
        }
        log_data.special_info = AppProtoLogsInfo::Mysql(self.info);
    }

    fn greeting(&mut self, payload: &[u8]) -> bool {
        let mut remain = payload.len();
        if remain < PROTOCOL_VERSION_LEN {
            return false;
        }
        self.info.protocol_version = payload[PROTOCOL_VERSION_OFFSET];
        remain -= PROTOCOL_VERSION_LEN;
        let server_version_pos = payload[SERVER_VERSION_OFFSET..]
            .iter()
            .position(|&x| x == SERVER_VERSION_EOF)
            .unwrap_or_default();
        if server_version_pos <= 0 {
            return false;
        }
        self.info.server_version = String::from_utf8_lossy(
            &payload[SERVER_VERSION_OFFSET..SERVER_VERSION_OFFSET + server_version_pos],
        )
        .into_owned();
        remain -= server_version_pos as usize;
        if remain < THREAD_ID_LEN {
            return false;
        }
        let thread_id_offset = THREAD_ID_OFFSET_B + server_version_pos + 1;
        self.info.server_thread_id = bytes::read_u32_le(&payload[thread_id_offset..]);
        self.l7_proto = L7Protocol::Mysql;
        true
    }

    fn request(&mut self, payload: &[u8]) -> bool {
        if payload.len() < COMMAND_LEN {
            return false;
        }
        self.info.command = payload[COMMAND_OFFSET];
        match self.info.command {
            MYSQL_COMMAND_QUIT | MYSQL_COMMAND_SHOW_FIELD => true,
            MYSQL_COMMAND_USE_DATABASE | MYSQL_COMMAND_QUERY => {
                self.request_string(&payload[COMMAND_OFFSET + COMMAND_LEN..]);
                true
            }
            _ => false,
        }
    }

    fn decode_compress_int(payload: &[u8]) -> u64 {
        let remain = payload.len();
        if remain == 0 {
            return 0;
        }
        let value = payload[0];
        match value {
            INT_FLAGS_2 if remain > INT_BASE_LEN + 2 => {
                bytes::read_u16_le(&payload[INT_BASE_LEN..]) as u64
            }
            INT_FLAGS_3 if remain > INT_BASE_LEN + 3 => {
                bytes::read_u16_le(&payload[INT_BASE_LEN..]) as u64
                    | ((payload[INT_BASE_LEN + 2] as u64) << 16)
            }
            INT_FLAGS_8 if remain > INT_BASE_LEN + 8 => {
                bytes::read_u64_le(&payload[INT_BASE_LEN..])
            }
            _ => value as u64,
        }
    }

    fn response(&mut self, payload: &[u8]) -> bool {
        let mut remain = payload.len();
        if remain < RESPONSE_CODE_LEN {
            return false;
        }
        self.info.response_code = payload[RESPONSE_CODE_OFFSET];
        remain -= RESPONSE_CODE_LEN;
        match self.info.response_code {
            MYSQL_RESPONSE_CODE_ERR => {
                if remain > ERROR_CODE_LEN {
                    self.info.error_code = bytes::read_u16_le(&payload[ERROR_CODE_OFFSET..]);
                    remain -= ERROR_CODE_LEN;
                }
                let error_message_offset =
                    if remain > SQL_STATE_LEN && payload[SQL_STATE_OFFSET] == SQL_STATE_MARKER {
                        SQL_STATE_OFFSET + SQL_STATE_LEN
                    } else {
                        SQL_STATE_OFFSET
                    };
                self.info.error_message =
                    String::from_utf8_lossy(&payload[error_message_offset..]).into_owned();
                true
            }
            MYSQL_RESPONSE_CODE_OK => {
                self.info.affected_rows =
                    MysqlLog::decode_compress_int(&payload[AFFECTED_ROWS_OFFSET..]);
                true
            }
            _ => true,
        }
    }

    fn parse(&mut self, payload: &[u8], proto: IpProtocol, direction: PacketDirection) -> bool {
        if proto != IpProtocol::Tcp {
            return false;
        }
        self.reset_logs();

        let mut header = Header::default();
        let offset = header.decode(payload);
        let msg_type = match header.check(direction, offset, payload, self.l7_proto) {
            Some(t) => t,
            None => return false,
        };

        let has_log = match msg_type {
            LogMessageType::Request => self.request(&payload[offset..]),
            LogMessageType::Response => self.response(&payload[offset..]),
            LogMessageType::Other => self.greeting(&payload[offset..]),
            _ => false,
        };
        if has_log {
            self.msg_type = msg_type;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod test {
    use std::fs;
    use std::path::Path;

    use super::*;

    use crate::{common::enums::PacketDirection, utils::test::Capture};

    const FILE_DIR: &str = "resources/test/flow_generator/mysql";

    fn run(name: &str) -> String {
        let pcap_file = Path::new(FILE_DIR).join(name);
        let capture = Capture::load_pcap(pcap_file, Some(1400));
        let mut packets = capture.as_meta_packets();
        if packets.is_empty() {
            return "".to_string();
        }

        let mut mysql = MysqlLog::default();
        let mut output: String = String::new();
        let first_dst_port = packets[0].lookup_key.dst_port;
        for packet in packets.iter_mut() {
            packet.direction = if packet.lookup_key.dst_port == first_dst_port {
                PacketDirection::ClientToServer
            } else {
                PacketDirection::ServerToClient
            };
            let payload = match packet.get_l4_payload() {
                Some(p) => p,
                None => continue,
            };
            mysql.parse(payload, packet.lookup_key.proto, packet.direction);
            output.push_str(&format!("{:?}\r\n", mysql.info));
        }
        output
    }

    #[test]
    fn check() {
        let files = vec![
            ("mysql.pcap", "mysql.result"),
            ("mysql-error.pcap", "mysql-error.result"),
            ("mysql-table-desc.pcap", "mysql-table-desc.result"),
            ("mysql-table-insert.pcap", "mysql-table-insert.result"),
            ("mysql-table-delete.pcap", "mysql-table-delete.result"),
            ("mysql-table-update.pcap", "mysql-table-update.result"),
            ("mysql-table-select.pcap", "mysql-table-select.result"),
            ("mysql-table-create.pcap", "mysql-table-create.result"),
            ("mysql-table-destroy.pcap", "mysql-table-destroy.result"),
            ("mysql-table-alter.pcap", "mysql-table-alter.result"),
            ("mysql-database.pcap", "mysql-database.result"),
        ];

        for item in files.iter() {
            let expected = fs::read_to_string(&Path::new(FILE_DIR).join(item.1)).unwrap();
            let output = run(item.0);

            if output != expected {
                let output_path = Path::new("actual.txt");
                fs::write(&output_path, &output).unwrap();
                assert!(
                    output == expected,
                    "output different from expected {}, written to {:?}",
                    item.1,
                    output_path
                );
            }
        }
    }
}
