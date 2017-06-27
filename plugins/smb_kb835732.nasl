#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12209);
  script_version("$Revision: 1.53 $");
  script_cvs_date("$Date: 2017/02/07 14:52:09 $");

  script_cve_id("CVE-2003-0533");
  script_bugtraq_id(10108);
  script_osvdb_id(5248);
  script_xref(name:"MSFT", value:"MS04-011");

  script_name(english:"MS04-011: Security Update for Microsoft Windows (835732) (uncredentialed check)");
  script_summary(english:"Checks for Microsoft Hotfix KB835732 by talking to the remote SMB service.");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the
LSASS service.");
  script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the function
'DsRolerUpgradeDownlevelServer' of the Local Security Authority Server
Service (LSASS) that allows an attacker to execute arbitrary code on
the remote host with SYSTEM privileges.

A series of worms (Sasser) are known to exploit this vulnerability in
the wild.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms04-011");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and
2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS04-011 Microsoft LSASS Service DsRolerUpgradeDownlevelServer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/04/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");
  script_family(english:"Windows");

  # Added OS fingerprinting due to FP against some non-Windows targets
  script_dependencies("smb_nativelanman.nasl", "smb_reg_service_pack.nasl", "samba_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("SMB/not_windows");
  script_require_ports(139, 445);

  exit(0);
}

include("misc_func.inc");
include("audit.inc");
include("smb_func.inc");

# Check OS due to FP against some non-Windows targets:
#  - Solaris SMB/CIFS service
#  - Linux-based HP Backup Storeonce 2700
#
# Nessus should be able to identify OS for targets with SMB server
# running, as information in an SMB SessionSetupAndX response is used
# as one source for OS identification.
#
# Make sure OS is detected. If OS is not detected, SMB is unlikely
# to be running, so skipping the check.
os = get_kb_item_or_exit("Host/OS");

# Skip non-Windows targets
if ("windows" >!< tolower(os)) audit(AUDIT_OS_NOT, "Windows");

function gssapi()
{
 return raw_string(0x60, 0x58,0x06,0xFF,0x06,0xFF,0x06,0x0F,0x05,0x0F,0x02,0xFF,0x06,0xFF,0xFF,0xFF,0xFF, 0x06,0x00,0x06,0x00,0x2A,0x00,0x00,0x00,0x0A,0x00,0x0A,0x00,0x20,0x00,0x00,0x00, 0x42,0x4C,0x49,0x4E,0x47,0x42,0x4C,0x49,0x4E,0x47,0x4D,0x53,0x48,0x4F,0x4D,0x45, 0x2A,0xFF,0x7F,0x74,0x6F,0xFF,0x0A,0x0B,0x9E,0xFF,0xE6,0x56,0x73,0x37,0x57,0x37, 0x0A,0x0B,0x0C);
}

name = kb_smb_name();
domain = kb_smb_domain();

port = int(get_kb_item("SMB/transport"));

if ( ! port )
{
 port = 445;
 soc  = 0;
 if ( get_port_state(port) )
 {
  soc = open_sock_tcp(port);
 }
 if ( ! soc )
 {
  port = 139;
  if ( ! get_port_state(port) ) audit(AUDIT_PORT_CLOSED, port);
 }
}

if ( ! soc ) soc = open_sock_tcp(port);
if ( ! soc ) audit(AUDIT_SOCK_FAIL, port);

session_init (socket:soc, hostname:name);

if ( port == 139 )
{
 if (netbios_session_request () != TRUE)
   exit (0);
}

ret = smb_negotiate_protocol ();
if (!ret)
  exit (0);

# Some checks in the header first
header = get_smb_header (smbblob:ret);
if (!ret)
  exit (0);

if (smb_check_success (data:ret) == FALSE)
  exit (0);

code = get_header_command_code (header:header);
if (code != SMB_COM_NEGOTIATE)
  exit (0);

# We now parse/take information in SMB parameters
parameters = get_smb_parameters (smbblob:ret);
if (!parameters)
  exit (0);

DialectIndex = get_word (blob:parameters, pos:0);

if (DialectIndex > (supported_protocol-1))
  exit (0);

if (protocol[DialectIndex] != "NT LM 0.12")
  exit (0);

SessionKey = get_dword (blob:parameters, pos:15);
Capabilities = get_dword (blob:parameters, pos:19);

if (Capabilities & CAP_UNICODE)
  session_set_unicode (unicode:1);
else
  session_set_unicode (unicode:0);

if (Capabilities & CAP_EXTENDED_SECURITY)
  session_add_flags2 (flag:SMB_FLAGS2_EXTENDED_SECURITY);
else
  exit (0);

header = smb_header (Command: SMB_COM_SESSION_SETUP_ANDX,
                     Status: nt_status (Status: STATUS_SUCCESS));

securityblob = gssapi();

parameters = raw_byte (b:255) + # no further command
             raw_byte (b:0) +
             raw_word (w:0) +
             raw_word (w:session_get_buffersize()) +
             raw_word (w:1) +
             raw_word (w:0) +
             raw_dword (d:SessionKey) +
             raw_word (w:strlen(securityblob)) +
             raw_dword (d:0) +
             raw_dword (d: CAP_UNICODE * session_is_unicode() | CAP_LARGE_FILES | CAP_NT_SMBS | CAP_STATUS32 | CAP_LEVEL_II_OPLOCKS | CAP_NT_FIND | CAP_EXTENDED_SECURITY);

parameters = smb_parameters (data:parameters);

# If strlen (securityblob) odd add 1 pad byte
if ((strlen (securityblob) % 2) == 0)
  securityblob += raw_string(0x00);

data = securityblob +
       cstring (string:"Unix") +
       cstring (string:"Nessus") +
       cstring (string:domain);

data = smb_data (data:data);

packet = netbios_packet (header:header, parameters:parameters, data:data);

ret = smb_sendrecv (data:packet);
if (!ret)
  audit(AUDIT_HOST_NOT, "affected");

# Some checks in the header first
header = get_smb_header (smbblob:ret);
if (!ret)
  audit(AUDIT_HOST_NOT, "affected");

# STATUS_INVALID_PARAMETER -> patched
# STATUS_MORE_PROCESSING_REQUIRED -> vulnerable

code = get_header_nt_error_code(header:header);
if ( code == STATUS_MORE_PROCESSING_REQUIRED) security_hole(port);
else audit(AUDIT_HOST_NOT, "affected");
