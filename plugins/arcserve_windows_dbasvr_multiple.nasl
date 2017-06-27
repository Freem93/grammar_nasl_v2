#
# (C) Tenable Network Security, Inc.
#

# BAB r11.5 sp1 and below - QO81201
# BAB r11.1 - QO82863
# BAB r11.0 - QI82917
# BEB r10.5 - QO82858
# BAB v9.01 - QO82856


include("compat.inc");

if (description)
{
 script_id(22511);
 script_version ("$Revision: 1.19 $");

 script_cve_id("CVE-2006-5142", "CVE-2006-5143");
 script_bugtraq_id(20364, 20365);
 script_osvdb_id(29533, 29534, 29535, 29580, 31318);

 script_name(english:"CA BrightStor ARCserve Backup DBASVR for Windows Multiple Remote Buffer Overflows");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"This host is running BrightStor ARCServe DBA server for Windows.

The remote version of this software is affected by multiple buffer
overflow vulnerabilities. 

An attacker, by sending a specially crafted packet, may be able to
execute code on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.tippingpoint.com/security/advisories/TSRT-06-11.html" );
 # https://web.archive.org/web/20061017184949/http://supportconnectw.ca.com/public/storage/infodocs/basbr-secnotice.asp
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eed70140" );
 script_set_attribute(attribute:"solution", value:
"Apply service pack 2 for Arcserve 11.5 or install the security patch." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'CA BrightStor ARCserve Message Engine Heap Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/10/06");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/10/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/10/05");
 script_cvs_date("$Date: 2017/04/28 14:01:58 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Check buffer overflow in BrightStor ARCServe for Windows DBASVR");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");
 script_require_ports (6071);

 script_dependencies("arcserve_discovery_service_detect.nasl", "os_fingerprint.nasl");
 script_require_keys("ARCSERVE/Discovery/Version");
 exit(0);
}


include ('smb_func.inc');

function RPC_Bind ()
{
 local_var ret, resp, soc;

 soc = session_get_socket ();

 ret = dce_rpc_bind(cid:session_get_cid(), uuid:"88435ee0-861a-11ce-b86b-00001b27f656", vers:1);
 send (socket:soc, data:ret);
 resp = recv (socket:soc, length:4096);

 if (!resp)
   return -1;

 ret = dce_rpc_parse_bind_ack (data:resp);
 if (isnull (ret) || (ret != 0))
   return -1;

 return 0;
}


 
function SERGetAgentDisplayName ()
{
 local_var data, ret, resp, val, soc;

 soc = session_get_socket ();

 session_set_unicode (unicode:0);
 
 data = 
        class_name (name:crap(data:"A", length:0x10)) +
        raw_dword(d:100);

 session_set_unicode (unicode:1);

 ret = dce_rpc_request (code:0x00, data:data);
 send (socket:soc, data:ret);
 resp = recv (socket:soc, length:4096);

 resp = dce_rpc_parse_response (data:resp);
 if (strlen(resp) != 20)
   return 0;

 val = get_dword (blob:resp, pos:16);
 if (val == 5)
   return 1;

 return 0;
}

ver = get_kb_item("ARCSERVE/Discovery/Version");
if (!ver) exit(0);

matches = eregmatch(string:ver, pattern:"^[a-z]([0-9]+)\.([0-9]+) \(build ([0-9]+)\)$");
if (isnull(matches)) exit(0);

ver = matches[1];

# Exit on version > 12 (safeapi)
if (int(ver) > 11) exit(0);

port = 6071;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp (port);
if (!soc) exit (0);

session_init (socket:soc);

ret = RPC_Bind ();
if (ret != 0)
  exit (0);

ret = SERGetAgentDisplayName ();
if (ret == 1)
  security_hole(port);

close (soc);
