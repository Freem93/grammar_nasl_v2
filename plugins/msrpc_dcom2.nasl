#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11835);
 script_version("$Revision: 1.68 $");
 script_cvs_date("$Date: 2014/07/11 21:44:07 $");

 script_cve_id("CVE-2003-0715", "CVE-2003-0528", "CVE-2003-0605");
 script_bugtraq_id(8458, 8460);
 script_osvdb_id(11460, 11797, 2535);
 script_xref(name:"MSFT", value:"MS03-039");

 script_name(english:"MS03-039: Microsoft RPC Interface Buffer Overrun (824146) (uncredentialed check)");
 script_summary(english:"Checks if the remote host has a patched RPC interface (KB824146)");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows that has a flaw in its
RPC interface, which may allow an attacker to execute arbitrary code
and gain SYSTEM privileges.

An attacker or a worm could use it to gain the control of this host.

Note that this is NOT the same bug as the one described in MS03-026,
which fixes the flaw exploited by the 'MSBlast' (or LoveSan) worm." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms03-039");
 script_set_attribute(attribute:"solution", value:"Microsoft has released patches for Windows NT, 2000, XP, and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/20");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/09/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/09/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_require_ports(135, 139, 445);
 script_dependencies("smb_nativelanman.nasl");
 exit(0);
}

#

include ('smb_func.inc');

function RemoteGetClassObject ()
{
 local_var fid, data, rep, ret;

 fid = bind_pipe (pipe:"\epmapper", uuid:"000001a0-0000-0000-c000-000000000046", vers:0);
 if (isnull (fid))
   return 0;

 data = raw_word (w:5) +
        raw_word (w:6) +
        raw_dword (d:1) +
        raw_dword (d:0) +
        encode_uuid (uuid:"54454e41-424c-454e-4554-574f524b5345") +
	raw_dword (d:0) +
        raw_dword (d:0x20000) +
	raw_dword (d:12) +
        raw_dword (d:12) +
	crap (data:"A", length:12) +
        raw_dword (d:0);


 data = dce_rpc_pipe_request (fid:fid, code:0x03, data:data);
 if (!data)
   return 0;

 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen(rep) != 16))
   return 0;

 ret = get_dword (blob:rep, pos:strlen(rep)-4);
 if ((ret == 0x8001011d) || (ret == 0x80070057) || (ret == 0x80070005))
   return 0;

 return 1;
}

os = get_kb_item ("Host/OS/smb") ;
if ("Windows" >!< os) exit(0);

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
 set_kb_item (name:"SMB/KB824146_launched", value:TRUE);

 ret = RemoteGetClassObject();
 if (ret == 1)
   security_hole(port:port);
 else
   set_kb_item(name:"SMB/KB824146", value:TRUE);

 NetUseDel();
}
