#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22510);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2017/04/28 14:01:58 $");

 script_cve_id("CVE-2006-5142", "CVE-2006-5143");
 script_bugtraq_id(20364, 20365);
 script_osvdb_id(29533, 29534, 29535, 29580, 31318);

 script_name(english:"CA BrightStor ARCserve Backup for Windows Multiple Remote Buffer Overflows (QO81201)");
 script_summary(english:"Check buffer overflow in BrightStor ARCServe for Windows");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"This host is running BrightStor ARCServe for Windows.

The remote version of this software has multiple buffer overflow
vulnerabilities. 

An attacker, by sending a specially crafted packet, may be able to
execute code on the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-06-031.html");
 # https://web.archive.org/web/20061017184949/http://supportconnectw.ca.com/public/storage/infodocs/basbr-secnotice.asp
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eed70140");
 script_set_attribute(attribute:"solution", value:
"Apply service pack 2 for Arcserve 11.5 or install the security patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'CA BrightStor ARCserve Message Engine Heap Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/06");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/10/05");
 script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/05");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:arcserve_backup");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");
 script_require_ports (6503);
 exit(0);
}


include ('smb_func.inc');

function RPC_Bind ()
{
 local_var ret, resp, soc;

 soc = session_get_socket ();

 ret = dce_rpc_bind(cid:session_get_cid(), uuid:"dc246bf0-7a7a-11ce-9f88-00805fe43838", vers:1);
 send (socket:soc, data:ret);
 resp = recv (socket:soc, length:4096);

 if (!resp)
   return -1;

 ret = dce_rpc_parse_bind_ack (data:resp);
 if (isnull (ret) || (ret != 0))
   return -1;

 return 0;
}


function RPC_QSICreateQueue ()
{
 local_var data, ret, resp, val, soc;

 soc = session_get_socket ();

 session_set_unicode (unicode:0);

 data = 
	class_name (name:crap(data:"A", length:0x31)) + 
	raw_dword (d:1) +
	class_name (name:"nessus");

 session_set_unicode (unicode:1);

 ret = dce_rpc_request (code:0x01, data:data);
 send (socket:soc, data:ret);
 resp = recv (socket:soc, length:4096);

 resp = dce_rpc_parse_response (data:resp);
 if (strlen(resp) != 8)
   return 0;

 val = get_dword (blob:resp, pos:4);
 if (val != 3)
   return 1;

 return 0;
}



port = 6503;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp (port);
if (!soc) exit (0);

session_init (socket:soc);

ret = RPC_Bind ();
if (ret != 0)
  exit (0);

ret = RPC_QSICreateQueue ();
if (ret != 0)
  security_hole(port);

close (soc);
