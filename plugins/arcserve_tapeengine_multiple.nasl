#
# (C) Tenable Network Security, Inc.
#

# BAB r11.5 - QO84983
# BAB r11.1 - QO84984
# BAB r11.0 - QI82917
# BEB r10.5 - QO84986
# BAB v9.01 - QO84985


include("compat.inc");

if (description)
{
 script_id(24013);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2017/04/28 14:01:58 $");

 script_cve_id("CVE-2006-6076", "CVE-2007-0168", "CVE-2007-0169");
 script_bugtraq_id(21221, 22006, 22010);
 script_osvdb_id(30637, 31318, 31327);

 script_name(english:"CA BrightStor ARCserve Backup Tape Engine Multiple Remote Overflows (QO84983)");
 script_summary(english:"Check buffer overflow in BrightStor ARCServe for Windows");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"This host is running BrightStor ARCServe for Windows.

The remote version of this software has multiple buffer overflow
vulnerabilities in the Tape Engine MSRPC service. 

An attacker, by sending a specially crafted packet, may be able to
crash the affected service or execute code on the remote host.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?543ab108");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/452222/30/0/threaded");
 script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-07-002.html");
 script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-07-004.html");
 # https://web.archive.org/web/20070117230030/http://supportconnectw.ca.com/public/storage/infodocs/babimpsec-notice.asp
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9fda01ee");
 script_set_attribute(attribute:"solution", value:"Apply security patch QO84983.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'CA BrightStor ARCserve Message Engine Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/01/11");
 script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/07");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:arcserve_backup");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

 script_require_ports(6502);
 exit(0);
}


include ('smb_func.inc');

function RPC_Bind ()
{
 local_var ret, resp, soc;

 soc = session_get_socket ();

 ret = dce_rpc_bind(cid:session_get_cid(), uuid:"62b93df0-8b02-11ce-876c-00805f842837", vers:1);
 send (socket:soc, data:ret);
 resp = recv (socket:soc, length:4096);

 if (!resp)
   return -1;

 ret = dce_rpc_parse_bind_ack (data:resp);
 if (isnull (ret) || (ret != 0))
   return -1;

 return 0;
}


function RPCNewFSDevice ()
{
 local_var data, ret, resp, val, soc;

 soc = session_get_socket ();

 session_set_unicode (unicode:0);

 data = 
	raw_dword (d:1) +
	class_name (name:crap(data:"A", length:0x10)) ;

 session_set_unicode (unicode:1);

 ret = dce_rpc_request (code:0xCF, data:data);
 send (socket:soc, data:ret);
 resp = recv (socket:soc, length:4096);

 resp = dce_rpc_parse_response (data:resp);
 if (strlen(resp) != 4)
   return 0;

 # patch -> if (strlen(s) > 8) return 0x1d
 val = get_dword (blob:resp, pos:0);
 if (val != 0x1d)
   return 1;

 return 0;
}



port = 6502;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp (port);
if (!soc) exit (0);

session_init (socket:soc);

ret = RPC_Bind ();
if (ret != 0)
  exit (0);

ret = RPCNewFSDevice ();
if (ret != 0)
  security_hole(port);

close (soc);
