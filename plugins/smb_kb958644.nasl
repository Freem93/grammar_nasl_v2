#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34477);
 script_version("$Revision: 1.48 $");
 script_cvs_date("$Date: 2017/04/19 13:27:09 $");

 script_cve_id("CVE-2008-4250");
 script_bugtraq_id(31874);
 script_osvdb_id(49243);
 script_xref(name:"MSFT", value:"MS08-067");
 script_xref(name:"CERT", value:"827267");
 script_xref(name:"IAVA", value:"2008-A-0081");
 script_xref(name:"EDB-ID", value:"6824");
 script_xref(name:"EDB-ID", value:"7104");
 script_xref(name:"EDB-ID", value:"7132");

 script_name(english:"MS08-067: Microsoft Windows Server Service Crafted RPC Request Handling Remote Code Execution (958644) (ECLIPSEDWING) (uncredentialed check)");
 script_summary(english:"Determines the presence of update 958644.");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a remote code execution
vulnerability in the 'Server' service due to improper handling of RPC
requests. An unauthenticated, remote attacker can exploit this, via a
specially crafted RPC request, to execute arbitrary code with 'System'
privileges.

ECLIPSEDWING is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2017/04/14 by a group known as the Shadow
Brokers.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-067");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS08-067 Microsoft Server Service Relative Path Stack Corruption');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/23");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/10/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/23");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_set_attribute(attribute:"in_the_news", value:"true");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("smb_nativelanman.nasl","smb_login.nasl");
 if ( NASL_LEVEL >= 3200 )
  script_dependencies("smb_kb958644_ips.nbin");
 script_require_keys("Host/OS/smb");
 script_exclude_keys("SMB/Missing/MS08-067");
 script_require_ports(139, 445);
 exit(0);
}

#

include ('smb_func.inc');

if ( get_kb_item("SMB/KB958644/34821/Vulnerable") ) security_hole(kb_smb_transport());
if ( get_kb_item("SMB/KB958644/34821") ) exit(0);
if ( get_kb_item("SMB/Missing/MS08-067") ) exit(0);

function  NetPathCanonicalize ()
{
 local_var data, data2, fid, fid2, rep, ret;

 fid = bind_pipe (pipe:"\browser", uuid:"4b324fc8-1670-01d3-1278-5a47bf6ee188", vers:3);
 if (isnull (fid))
   return 0;

 fid2 = bind_pipe (pipe:"\browser", uuid:"6bffd098-a112-3610-9833-46c3f87e345a", vers:1);
 if (isnull (fid2))
   return 0;

 data2 = class_parameter (name:"", ref_id:0x20000) +
        class_name (name:crap(data:"\A", length:0x100)) +
	raw_dword (d:0) ;

 data = class_parameter (name:"", ref_id:0x20000) +
        class_name (name:"\" + crap(data:"A", length:0x23) + "\..\nessus") +
	class_name (name:"\nessus") +
	raw_dword (d:1) +
	raw_dword (d:0) ;

 data2 = dce_rpc_pipe_request (fid:fid2, code:0x0A, data:data2);
 if (!data2)
   return 0;

 data = dce_rpc_pipe_request (fid:fid, code:0x20, data:data);
 if (!data)
   return 0;


 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen(rep) != 4))
   return 0;

 ret = get_dword (blob:rep, pos:strlen(rep)-4);
 if (ret == 0)
   return 1;

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
 ret = NetPathCanonicalize ();
 if (ret == 1)
   security_hole(port:port);
 else
   set_kb_item(name:"SMB/KB958644/34477", value:TRUE);
 NetUseDel();
}
