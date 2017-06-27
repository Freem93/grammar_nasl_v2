#
# (C) Tenable Network Security, Inc.
#

# Windows XP SP1 can be identified remotely without harm, not Windows 2000

include("compat.inc");

if (description)
{
 script_id(18027);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2016/11/28 21:52:57 $");

 script_cve_id("CVE-2005-0059");
 script_bugtraq_id(13112);
 script_osvdb_id(15458);
 script_xref(name:"MSFT", value:"MS05-017");

 script_name(english:"MS05-017: Vulnerability in MSMQ Could Allow Code Execution (892944) (uncredentialed check)");
 script_summary(english:"Determines if hotfix 892944 has been installed");

 script_set_attribute(
  attribute:"synopsis",
  value:"Arbitrary code can be executed on the remote host."
 );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows is affected by a vulnerability in
Microsoft Message Queuing Service (MSMQ).

An attacker may exploit this flaw to execute arbitrary code on the
remote host with SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms05-017");
 script_set_attribute(
  attribute:"solution",
  value:"Microsoft has released a set of patches for Windows ME, XP, and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS05-017 Microsoft Message Queueing Service Path Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/12");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_nativelanman.nasl");
 script_require_keys("Host/OS/smb");
 script_require_ports(2103);
 exit(0);
}

#

include ('smb_func.inc');

function dce_rpc_parse_response2 (data)
{
 local_var resp, flag, len, alloc, tmp, dat;

 if (strlen (data) < 24)
   return NULL;

 flag = get_byte (blob:data, pos:3);
 len = get_word (blob:data, pos:8) - 24;
 alloc = get_dword (blob:data, pos:16);

 if (strlen (data) < (24 + len))
   return NULL;

 return substr (data, 24, 24 + len - 1);
}

os = get_kb_item("Host/OS/smb");
if ( "Windows 5.1" >!< os ) exit (0);

port = 2103;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp (port);
if (!soc) exit (0);

host_ip = get_host_ip();

ret = dce_rpc_bind(cid:session_get_cid(), uuid:"fdb3a030-065f-11d1-bb9b-00a024ea5525", vers:1);
send (socket:soc, data:ret);
resp = recv (socket:soc, length:4096);

if (!resp)
{
 close (soc);
 exit (0);
}

ret = dce_rpc_parse_bind_ack (data:resp);
if (isnull (ret) || (ret != 0))
{
 close (soc);
 exit (0);
}


data = raw_string (
        0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0x12, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
        0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x54, 0x00, 0x43, 0x00,
        0x50, 0x00, 0x3A, 0x00, 0x31, 0x00, 0x32, 0x00, 0x37, 0x00, 0x2E, 0x00, 0x31, 0x00, 0x30, 0x00,
        0x2E, 0x00, 0x31, 0x00, 0x30, 0x00, 0x2E, 0x00, 0x31, 0x00, 0x30, 0x00, 0x33, 0x00, 0x5C, 0x00,
        0x50, 0x00, 0x52, 0x00, 0x49, 0x00, 0x56, 0x00, 0x41, 0x00, 0x54, 0x00, 0x45, 0x00, 0x24, 0x00,
        0x5C, 0x00, 0x6E, 0x00, 0x65, 0x00, 0x73, 0x00, 0x73, 0x00, 0x75, 0x00, 0x73, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x06, 0x01, 0x11, 0x1b, 0x1e,
        0x0c, 0x09, 0x0d, 0x00, 0x08, 0x1b, 0x17, 0x05, 0x12, 0x07, 0x0f, 0x10, 0x0d, 0x1a, 0x11, 0x1a
);

ret = dce_rpc_request (code:0x02, data:data);
send (socket:soc, data:ret);
resp = recv (socket:soc, length:4096);

close (soc);

resp = dce_rpc_parse_response2 (data:resp);
if (strlen(resp) != 36)
  exit (0);

# patched = 0xC00E0045
# not patched = 0xC00E0003

val = get_dword (blob:resp, pos:strlen(resp)-4);
if (val == 0xC00E0003)
  security_hole(port);
