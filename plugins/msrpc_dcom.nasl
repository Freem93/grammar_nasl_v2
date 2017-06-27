#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11808);
 script_version("$Revision: 1.42 $");
 script_cvs_date("$Date: 2016/11/28 21:52:57 $");

 script_cve_id("CVE-2003-0352");
 script_bugtraq_id(8205);
 script_osvdb_id(2100);
 script_xref(name:"MSFT", value:"MS03-026");

 script_name(english:"MS03-026: Microsoft RPC Interface Buffer Overrun (823980) (uncredentialed check)");
 script_summary(english:"[LSD] Critical security vulnerability in Microsoft Operating Systems");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a flaw in the function
RemoteActivation() in its RPC interface that could allow an attacker to
execute arbitrary code on the remote host with the SYSTEM privileges.

A series of worms (Blaster) are known to exploit this vulnerability in the
wild.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms03-026");
 script_set_attribute(attribute:"solution", value:"Microsoft has released patches for Windows NT, 2000, XP, and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS03-026 Microsoft RPC DCOM Interface Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/16");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/07/28");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("smb_nativelanman.nasl", "msrpc_dcom2.nasl");
 script_require_ports(139, 445);
 exit(0);
}

#

include ('smb_func.inc');

if(get_kb_item("SMB/KB824146"))exit(0);
if(!get_kb_item("SMB/KB824146_launched"))exit(0);

function RemoteActivation ()
{
 local_var fid, data, rep, ret;

 fid = bind_pipe (pipe:"\epmapper", uuid:"4d9f4ab8-7d1c-11cf-861e-0020af6e7c57", vers:0);
 if (isnull (fid))
   return 0;

 data = # DCOM information
	raw_word (w:5) +
        raw_word (w:6) +
        raw_dword (d:1) +
        raw_dword (d:0) +
        encode_uuid (uuid:"54454e41-424c-454e-4554-574f524b5345") +
	raw_dword (d:0) +

	# CLSID
	encode_uuid (uuid:"53454e5b-5553-5d53-5b4e-45535355535d") +

	# ObjectName
	class_parameter (ref_id:0x20004, name:"\\A"+raw_string(0)+"A\\AA") +

	# NULL pointer
	raw_dword (d:0) +

	# ClientImpLevel
	raw_dword (d:0) +
	# Modes
	raw_dword (d:0) +

	# interfaces (only 1)
	raw_dword (d:1) +
	raw_dword (d:0x20008) +
	raw_dword (d:1) +
	encode_uuid (uuid:"00000000-0000-0000-0000-000000000000") +

	# rest of data
	raw_dword (d:0) +
	raw_dword (d:0);

 data = dce_rpc_pipe_request (fid:fid, code:0x00, data:data);
 if (!data)
   return 0;

 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen(rep) != 68))
   return 0;

 ret = get_dword (blob:rep, pos:strlen(rep)-24);
 if ((ret == 0x80080004) || (ret == 0x80070005))
   return 0;

 return 1;
}

os = get_kb_item ("Host/OS/smb") ;
if (("Windows 5.1" >!< os) && ("Windows 5.0" >!< os) && ("Windows 5.2" >!< os) && ("Windows 4.0" >< os))
  exit(0);

port = get_kb_item("SMB/transport");
if(!port)port = 445;

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

name	= kb_smb_name();

session_init(socket:soc, hostname:name);

r = NetUseAdd(share:"IPC$");
if ( r == 1 )
{
 ret = RemoteActivation();
 if (ret == 1)
   security_hole(port:port);

 NetUseDel();
}
