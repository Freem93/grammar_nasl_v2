#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(20368);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2013/11/04 02:28:18 $");

 script_cve_id("CVE-2004-0899", "CVE-2004-0900");
 script_bugtraq_id(11919, 11920);
 script_osvdb_id(12371, 12377);
 script_xref(name:"MSFT", value:"MS04-042");

 script_name(english:"MS04-042: Windows NT Multiple DHCP Vulnerabilities (885249) (uncredentialed check)");
 script_summary(english:"Checks if MS04-042 is installed");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host through the DHCP service.");
 script_set_attribute(attribute:"description", value:
"The remote host has the Windows DHCP server installed.

There is a flaw in the remote version of this server that may allow an
attacker to execute arbitrary code on the remote host with SYSTEM
privileges." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms04-042");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows NT.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/03");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("dcetest.nasl", "smb_nativelanman.nasl");
 script_require_keys("Host/OS/smb", "Services/DCE/6bffd098-a112-3610-9833-46c3f874532d");
 exit(0);
}

#

include ('smb_func.inc');

os = get_kb_item ("Host/OS/smb") ;
if ( !os || "Windows 4.0" >!< os )
  exit(0);

# DHCPSERVER Service
port = get_kb_item ("Services/DCE/6bffd098-a112-3610-9833-46c3f874532d");
if (!port)
  exit (0);

if (!get_port_state (port))
  exit (0);

soc = open_sock_tcp (port);
if (!soc) exit (0);

ret = dce_rpc_bind(cid:session_get_cid(), uuid:"6bffd098-a112-3610-9833-46c3f874532d", vers:1);
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


# DhcpGetVersion - opcode : 0x1C
#
# long  DhcpGetVersion (
#  [in][unique][string] wchar_t * arg_1,
#  [in] long arg_2,
#  [in, out] long * arg_3,
#  [in] long arg_4,
#  [out] struct_1 ** arg_5,
#  [out] long * arg_6,
#  [out] long * arg_7
# );


data = class_parameter (ref_id:0x20000, name:get_host_ip()) +
       raw_dword (d:0) +
       raw_dword (d:0) +
       raw_dword (d:0) ;


ret = dce_rpc_request (code:0x1C, data:data);
send (socket:soc, data:ret);
resp = recv (socket:soc, length:4096);

close (soc);

resp = dce_rpc_parse_response (data:resp);
if (strlen(resp) != 12)
  exit (0);

val = get_dword (blob:resp, pos:strlen(resp)-4);
if (val != 0)
  exit (0);

major = get_dword (blob:resp, pos:0);
minor = get_dword (blob:resp, pos:4);

# patched version 4.1
# vulnerable 1.1

if (major < 4)
  security_hole(port);
