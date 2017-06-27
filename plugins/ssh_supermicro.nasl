#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71533);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/15 13:52:58 $");

  script_osvdb_id(99595);

  script_name(english:"SuperMicro Device Uses Default SSH Host Key");
  script_summary(english:"Checks if the device is using default host key");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is using the default SSH host key for this service,
whose private key is public knowledge.");
  script_set_attribute(attribute:"description", value:
"The SSH host key used by the remote host has not been changed from the
default host key that is hardwired into the firmware.  The private key
corresponding to this host key is shared across all devices running the
same firmware, meaning that the remote host's key certificate cannot be
trusted.");
  # https://community.rapid7.com/community/metasploit/blog/2013/11/06/supermicro-ipmi-firmware-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99a8b71e");
  script_set_attribute(attribute:"solution", value:"Configure the device to use a device-specific host key.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UC");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:supermicro:bmc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("obj.inc");
include("ssh_func.inc");

global_var port;

function parse_ssh_hostkey(blob)
{
  local_var field, fields, key, pos;

  key = make_array();
  pos = 0;

  key["alg"] = getstring(buffer:blob, pos:pos);
  pos += 4 + strlen(key["alg"]);

  if (key["alg"] == "ssh-rsa")
    fields = make_list("e", "n");
  else if (key["alg"] == "ssh-dss")
    fields = make_list("p", "q", "g", "y");
  else
    exit(1, "Unrecognized key type '" + key["alg"] +  " received on port " + port + ".");

  foreach field (fields)
  {
    key[field] = getstring(buffer:blob, pos:pos);
    if (isnull(key[field]))
      exit(1, "Failed to parse '" + field + "' of " + key["alg"] +  " key on port " + port + ".");

    pos += 4 + strlen(key[field]);
  }

  return key;
}

# This key's fingerprint is: 21:0e:54:f2:0c:d8:bc:a1:1c:72:e0:3b:e9:ae:f9:82.
KEY_RSA = make_array(
  "alg", 'ssh-rsa',
  "e", raw_string(0x01, 0x00, 0x01),
  "n", raw_string(
    0x00, 0xE4, 0x46, 0xA4, 0x75, 0x55, 0x18, 0x07,
    0x38, 0xE3, 0x7C, 0x33, 0xB6, 0x02, 0x36, 0x72,
    0x06, 0xF2, 0x4D, 0x33, 0xBA, 0x40, 0x0D, 0xFE,
    0xBE, 0x0B, 0xE5, 0xF3, 0xCA, 0x4E, 0xF5, 0xA6,
    0x76, 0x17, 0xB5, 0xED, 0x49, 0xF1, 0xCB, 0x03,
    0xDC, 0xF9, 0x3C, 0x92, 0x8D, 0x7A, 0x8D, 0xB1,
    0x74, 0x3F, 0x8C, 0xF2, 0xC6, 0xBE, 0x93, 0xB9,
    0xBA, 0x84, 0x86, 0xDD, 0xD8, 0x13, 0xD8, 0xDE,
    0xCD, 0x51, 0xD0, 0x2D, 0x74, 0xBE, 0x04, 0x9D,
    0xBF, 0x3B, 0x75, 0x7E, 0xF2, 0x4D, 0xB2, 0x53,
    0x27, 0x33, 0x0C, 0xC5, 0x36, 0xFD, 0x1D, 0x22,
    0x35, 0x48, 0xBD, 0xBF, 0xE6, 0x24, 0x9E, 0x7F,
    0x20, 0x15, 0x56, 0x8D, 0x7E, 0x47, 0xC0, 0xCC,
    0x98, 0x5A, 0x93, 0x59, 0xAD, 0x9E, 0x14, 0x7A,
    0x03, 0xF4, 0x8A, 0x31, 0x15, 0x23, 0x52, 0x4D,
    0xAA, 0xD3, 0x65, 0x08, 0x26, 0x1F, 0x5A, 0x19,
    0x62, 0x86, 0x57
  )
);

# This key's fingerprint is: d6:b4:e5:9c:1a:4d:5e:4c:66:a7:f4:51:5f:d4:e0:30.
KEY_DSA = make_array(
  "alg", 'ssh-dsa',
  "p", raw_string(
    0x00, 0x92, 0x8A, 0xB4, 0xA6, 0x41, 0x10, 0x20,
    0x3E, 0xC2, 0xDB, 0xD8, 0xB6, 0xB1, 0x1E, 0x33,
    0x24, 0xF3, 0x92, 0x6D, 0xD7, 0xFF, 0x82, 0x1F,
    0x0B, 0xA1, 0x3C, 0x35, 0xC9, 0xD9, 0xA2, 0xE3,
    0x02, 0x1D, 0x89, 0xF7, 0x17, 0xDE, 0xB8, 0xFA,
    0x91, 0xBB, 0x99, 0x1B, 0x24, 0x64, 0x08, 0xBB,
    0x3F, 0xDE, 0x55, 0xC0, 0x96, 0x31, 0xE9, 0x32,
    0xE4, 0x88, 0xAF, 0xCC, 0x34, 0xA2, 0x21, 0xF2,
    0x69, 0x3C, 0x33, 0x85, 0xF1, 0xBB, 0x65, 0x12,
    0x21, 0x76, 0xE5, 0x91, 0x33, 0xEB, 0x68, 0xF6,
    0x07, 0xC9, 0x58, 0x13, 0x91, 0xF6, 0x62, 0xB7,
    0xA1, 0x7D, 0xA9, 0x34, 0x7C, 0x70, 0x03, 0xA5,
    0x1E, 0xDA, 0x18, 0xFB, 0xD1, 0xA0, 0x2A, 0x65,
    0x8C, 0x2C, 0x2F, 0xB1, 0x78, 0xE8, 0x0F, 0xB6,
    0x81, 0x11, 0xBD, 0x4C, 0xAE, 0xBA, 0x9A, 0xD7,
    0xB0, 0x0C, 0xED, 0x67, 0xD0, 0xB6, 0x04, 0xA5,
    0xA3
  ),
  "q", raw_string(
    0x00, 0xE7, 0x3D, 0x73, 0x77, 0x9F, 0x68, 0x35,
    0xC7, 0x1B, 0x18, 0x66, 0xC6, 0x90, 0xA5, 0xD3,
    0xEE, 0x8A, 0x36, 0xF5, 0xB5
  ),
  "g", raw_string(
    0x3B, 0xFC, 0x8A, 0x45, 0xCB, 0x79, 0x92, 0x82,
    0x9B, 0xBF, 0x4E, 0x69, 0x81, 0xB9, 0x82, 0xDC,
    0x71, 0xD4, 0x53, 0x08, 0xDB, 0x78, 0xF7, 0x75,
    0x37, 0xC0, 0xC2, 0xDB, 0xFC, 0x97, 0x54, 0x06,
    0xEE, 0x21, 0xD4, 0x53, 0x3A, 0x27, 0x90, 0xD2,
    0xA3, 0x37, 0x10, 0xEF, 0x40, 0x13, 0x82, 0x5A,
    0x4B, 0x2D, 0x86, 0xB7, 0x46, 0xEE, 0x73, 0xB6,
    0xFF, 0x3B, 0x12, 0xCB, 0xBC, 0x73, 0xB0, 0x87,
    0xFD, 0x30, 0x07, 0xF8, 0x66, 0x79, 0xFF, 0x72,
    0xC9, 0xB5, 0x2F, 0xFF, 0x1C, 0x90, 0xED, 0xFB,
    0x9D, 0xF2, 0xCB, 0x80, 0xA0, 0xC0, 0xEF, 0x29,
    0x70, 0xA6, 0xD8, 0xA3, 0x4A, 0xDF, 0x47, 0x2E,
    0x3F, 0x41, 0xD1, 0x57, 0x59, 0xE0, 0x54, 0xB4,
    0xCD, 0x97, 0x37, 0x88, 0x47, 0xBD, 0xB6, 0x81,
    0x27, 0x47, 0xF3, 0x3F, 0x58, 0x17, 0x23, 0x51,
    0x87, 0xBF, 0x3D, 0xCE, 0x43, 0x15, 0x88, 0x0A
  ),
  "y", raw_string(
    0x2F, 0x65, 0x59, 0x64, 0xE8, 0x65, 0xFE, 0xB8,
    0x6A, 0x6A, 0x2D, 0xD5, 0xB8, 0x17, 0x57, 0x2D,
    0x92, 0xEA, 0x94, 0x9E, 0x42, 0x06, 0xCD, 0x1C,
    0xE2, 0x27, 0xD1, 0xA4, 0xE3, 0xAB, 0xCE, 0x38,
    0x50, 0x8F, 0xC5, 0x4F, 0x1B, 0x51, 0x72, 0xC6,
    0xCE, 0xF0, 0xBB, 0x66, 0xFD, 0xD2, 0x39, 0x1D,
    0x38, 0x60, 0x7E, 0xFF, 0x2C, 0x33, 0x14, 0xA1,
    0xFD, 0xB2, 0xEB, 0xC1, 0x0E, 0x09, 0xB1, 0xFD,
    0x61, 0x3F, 0x26, 0x1C, 0xDA, 0x8B, 0x75, 0x9F,
    0x53, 0xC4, 0xE5, 0xAF, 0xF3, 0x05, 0x1A, 0x0D,
    0x7E, 0x4E, 0xF4, 0x9F, 0x09, 0x5E, 0x78, 0x0B,
    0xC2, 0x5F, 0x94, 0xF8, 0xE3, 0x62, 0xB6, 0xC7,
    0xA0, 0xFC, 0xFA, 0xC4, 0x64, 0xA9, 0x8F, 0xDB,
    0xF7, 0x11, 0xE3, 0x6A, 0x45, 0xC2, 0xE4, 0xF3,
    0x6F, 0x9F, 0x7E, 0x35, 0x29, 0x04, 0x54, 0x06,
    0xB4, 0x64, 0xAE, 0xBE, 0xD8, 0x59, 0x16, 0xA2
  )
);

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);

_ssh_socket = open_sock_tcp(port);
if (!_ssh_socket) audit(AUDIT_SOCK_FAIL, port);

init();

server_version = ssh_exchange_identification();
if (!server_version)
  exit(1, "Failed to exchange version strings with server on port " + port + ".");

ret = ssh_kex2(server_version:server_version, nofingerprint:TRUE);
if (ret != 0)
  exit(1, "Failed to exchange SSH keys with server on port " + port + ".");

key = parse_ssh_hostkey(blob:server_host_key_blob);
if (!obj_cmp(key, KEY_RSA) && !obj_cmp(key, KEY_DSA))
  audit(AUDIT_LISTEN_NOT_VULN, "SSH", port);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n' + 'This SSH key is used by other devices, and therefore cannot be trusted :' +
    '\n';

  if (key["alg"] == "ssh-rsa")
  {
    report +=
      '\n  Algorithm   : RSA Encryption' +
      '\n  Fingerprint : 21:0E:54:F2:0C:D8:BC:A1:1C:72:E0:3B:E9:AE:F9:82' +
      '\n';
  }
  else
  {
    report +=
      '\n  Algorithm   : DSA Encryption' +
      '\n  Fingerprint : D6:B4:E5:9C:1A:4D:5E:4C:66:A7:F4:51:5F:D4:E0:30' +
      '\n';
  }
}

security_warning(port:port, extra:report);
