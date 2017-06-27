#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(21334);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2013/11/04 02:28:18 $");

 script_cve_id("CVE-2006-0034", "CVE-2006-1184");
 script_bugtraq_id(17905, 17906);
 script_osvdb_id(25335, 25336);
 script_xref(name:"MSFT", value:"MS06-018");

 script_name(english:"MS06-018: Vulnerability in Microsoft Distributed Transaction Coordinator Could Allow DoS (913580) (uncredentialed check)");
 script_summary(english:"Determines the presence of update 913580");

 script_set_attribute(attribute:"synopsis", value:"A vulnerability in MSDTC could allow remote code execution.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of MSDTC (Microsoft
Data Transaction Coordinator) service that is affected by several
remote code execution and denial of service vulnerabilities.

An attacker may exploit these flaws to obtain complete control of the
remote host (2000, NT4) or to crash the remote service (XP, 2003)." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms06-018");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 2000, XP and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/05/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/10");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("dcetest.nasl");
 script_require_keys("Services/DCE/906b0ce0-c70b-1067-b317-00dd010662da");
 exit(0);
}

#

include ('smb_func.inc');

port = get_kb_item ("Services/DCE/906b0ce0-c70b-1067-b317-00dd010662da");
if (!port)
  exit (0);

if (!get_port_state (port))
  exit (0);

context_handles = get_kb_list ("DCE/906b0ce0-c70b-1067-b317-00dd010662da/context_handle");
if (isnull(context_handles))
  exit (0);

foreach context_handle (context_handles)
{
 if (!isnull(context_handle))
   break;
}

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp (port);
if (!soc) exit (0);

host_ip = get_host_ip();

ret = dce_rpc_bind(cid:session_get_cid(), uuid:"906b0ce0-c70b-1067-b317-00dd010662da", vers:1);
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

session_set_unicode (unicode:1);

data = raw_dword (d:0) +

       # Type 1
       raw_dword (d:0) +
       raw_dword (d:0) +
       raw_dword (d:0) +
       raw_dword (d:0) +
       raw_dword (d:0) +
       raw_dword (d:0) +

       # need a valid context handle to pass the first check
       class_name (name:context_handle) +
       # a patched version will first check if the length is less than 17
       class_name (name:crap(data:"B", length:17)) +

       # need to be 37 bytes long to be a valid RPC packet
       # [size_is(37)] [in]  [string] wchar_t * element_57,
       # [size_is(37)] [in]  [string] wchar_t * element_58,
       class_name (name:crap(data:"A", length:36)) +
       class_name (name:crap(data:"A", length:36)) +

       # a patched version will first check if the length is 37 (36 + '\0')(IDL RPC)
       class_name (name:crap(data:"C", length:37)) +

       # Type 2
       raw_dword (d:0) +
       raw_dword (d:0) +
       raw_dword (d:0) +

       # [in]  [range(8,8)] long  element_65,
       # [size_is(element_65)] [in]  char  element_66,
       # range restriction is only present in the Windows XP/2003 version
       raw_dword (d:8) +
       raw_dword (d:8) +
       crap (data:raw_string(0), length:8)
 ;


ret = dce_rpc_request (code:0x07, data:data);
send (socket:soc, data:ret);
resp = recv (socket:soc, length:4096);
resp = dce_rpc_parse_response (data:resp);

if (strlen(resp) > 8)
  security_hole(port);
