#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(21696);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id("CVE-2006-2370", "CVE-2006-2371");
 script_bugtraq_id(18325, 18358);
 script_osvdb_id(26436, 26437);
 script_xref(name:"MSFT", value:"MS06-025");

 script_name(english:"MS06-025: Vulnerability in Routing and Remote Access Could Allow Remote Code Execution (911280) (uncredentialed check)");
 script_summary(english:"Determines the presence of update 911280 (remote check)");

 script_set_attribute(
  attribute:"synopsis",
  value:"It is possible to execute code on the remote host."
 );
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of RRAS (Routing and
Remote Access Service) that is affected by several memory corruption
vulnerabilities.

An attacker may exploit these flaws to execute code on the remote
service." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-025");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 2000, XP and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS06-025 Microsoft RRAS Service Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/07/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:windows:routingsvr");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("smb_nativelanman.nasl","smb_login.nasl");
 script_require_keys("Host/OS/smb");
 script_require_ports(139,445);
 exit(0);
}

#

include ('smb_func.inc');

global_var rpipe;

function  RasRpcDeleteEntry ()
{
 local_var fid, data, rep, ret;

 fid = bind_pipe (pipe:"\SRVSVC", uuid:"20610036-fa22-11cf-9823-00a0c911e5df", vers:1);
 if (isnull (fid))
   return 0;

 data = class_name (name:string("tns",rand())) +
	class_name (name:string("tns",rand())) ;

 data = dce_rpc_pipe_request (fid:fid, code:0x05, data:data);
 if (!data)
   return 0;

 rep = dce_rpc_parse_response (fid:fid, data:data);

 if (!rep || (strlen(rep) != 4))
   return 0;

 ret = get_dword (blob:rep, pos:0);
 if (ret == 0x26d)
   return 1;

 # patched == 0x80070005 (check if admin) or access denied
 return 0;
}

os = get_kb_item ("Host/OS/smb") ;
if ("Windows" >!< os) exit(0);

name	= kb_smb_name();
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:name);

r = NetUseAdd(share:"IPC$");
if ( r == 1 )
{
 ret = RasRpcDeleteEntry ();
 if (ret == 1)
   security_hole(port:port);

 NetUseDel();
}
