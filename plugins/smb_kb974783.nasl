#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(42443);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2015/01/15 16:37:17 $");

 script_cve_id("CVE-2009-2523");
 script_bugtraq_id(36921);
 script_osvdb_id(59855);
 script_xref(name:"MSFT", value:"MS09-064");

 script_name(english:"MS09-064: Vulnerability in the License Logging Service (974783) (uncredentialed check)");
 script_summary(english:"Determines if hotfix 974783 has been installed");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the Logging Service
that may allow an attacker to execute arbitrary code on the remote
host.

To exploit this flaw, an attacker would need to send a malformed
packet to the remote logging service and would be able to either
execute arbitrary code on the remote host or perform a denial of
service.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/MS09-064");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 2000.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/10");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/11/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated", "Host/OS/smb");
 script_require_ports(139, 445);
 exit(0);
}


include ('smb_func.inc');

function LlsrLicenseRequestW()
{
 local_var fid, data, rep, name;
 local_var code;

 fid = bind_pipe (pipe:"\llsrpc", uuid:"57674cd0-5200-11ce-a897-08002b2e9c6d", vers:1);
 if (isnull (fid))
   return -1;

 name = session_get_hostname();

 # only unicode is supported
 if (session_is_unicode ())
   name = class_name(name:name);
 else
 {
   session_set_unicode(unicode:1);
   name = class_name(name:name);
   session_set_unicode(unicode:0);
 }

 data = name +
	raw_dword (d:0) +
	raw_dword (d:0) +
	raw_byte(b:0) +
	raw_dword(d:0) +
	raw_dword(d:0) +
        raw_dword (d:0)+
        raw_dword (d:5)+
	'\xd4\xce\xc2\xcc\x00';



 data = dce_rpc_pipe_request (fid:fid, code:0x00, data:data);
 if (!data || strlen(data) != 48 )
   return 0;

 code = get_dword(blob:data, pos:strlen(data) - 4);
 if ( code == 0 )
	return 1;
 else
	return 0; # Patched version returns  0xc000000d
}

os = get_kb_item ("Host/OS/smb") ;
if ( ! os || "Windows 5.0" >!< os ) exit(0, "OS unknown");


port = get_kb_item("SMB/transport");
if(!port)port = 445;

if ( ! get_port_state(port) ) exit(0, "Port " + port + " is closed.");
soc = open_sock_tcp(port);
if ( ! soc ) exit(1, "Could not connect to port "+port+".");

name = kb_smb_name();
login = kb_smb_login();
pass = kb_smb_password();
dom  = kb_smb_domain();
session_init(socket:soc, hostname:name);
r = NetUseAdd(share:"IPC$", login:login, password:pass, domain:dom);
if ( r == 1 )
{
 ret = LlsrLicenseRequestW();
 NetUseDel();
 if ( ret < 0 )
   exit(1, "Could not connect to \llssvr");
 if (ret == 1)
 {
   security_hole(port:port);
   exit(0, "Host is vulnerable.");
 }
 else exit(0, "Host is patched.");
}
