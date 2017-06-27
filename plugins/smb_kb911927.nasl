#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(20928);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2013/11/04 02:28:18 $");

 script_cve_id("CVE-2006-0013");
 script_bugtraq_id(16636);
 script_osvdb_id(23134);
 script_xref(name:"MSFT", value:"MS06-008");

 script_name(english:"MS06-008: Vulnerability in Web Client Service Could Allow Remote Code Execution (911927) (uncredentialed check)");
 script_summary(english:"Determines the presence of update 911927 (remote check)");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the Web Client
service that may allow an attacker to execute arbitrary code on the
remote host.

To exploit this flaw, an attacker would need credentials to log into
the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-008");
 script_set_attribute( attribute:"solution", value:"Microsoft has released a set of patches for Windows XP and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/15");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:windows:webclntsvc");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("smb_nativelanman.nasl","smb_login.nasl");
 script_require_keys("Host/OS/smb");
 script_require_ports(139,445);
 exit(0);
}

#

include ('smb_func.inc');

global_var rpipe;

function  DavCreateConnection ()
{
 local_var fid, data, rep, ret;

 fid = bind_pipe (pipe:"\DAV RPC SERVICE", uuid:"c8cb7687-e6d3-11d2-a958-00c04f682e16", vers:1);
 if (isnull (fid))
   return 0;

 data = class_parameter (ref_id:0x20000, name:"c:") +
	class_name (name:"\\") +
	raw_dword (d:0) +
	class_parameter (ref_id:0x20008, name:crap(data:"A", length:0x101)) +
	class_parameter (ref_id:0x2000c, name:"tns") ;

 data = dce_rpc_pipe_request (fid:fid, code:0x00, data:data);
 if (!data)
   return 0;

 rep = dce_rpc_parse_response (fid:fid, data:data);

 if (!rep || (strlen(rep) != 4))
   return 0;

 ret = get_dword (blob:rep, pos:0);
 if (ret == 0x43)
   return 1;

 # patched == 0x57 (or access denied)
 return 0;
}

os = get_kb_item ("Host/OS/smb") ;
if ("Windows" >!< os) exit(0);

name	= kb_smb_name();
login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:name);

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r == 1 )
{
 ret = DavCreateConnection ();
 if (ret == 1)
   security_warning(port:port);

 NetUseDel();
}
