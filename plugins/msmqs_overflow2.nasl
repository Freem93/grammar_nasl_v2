#
# (C) Tenable Network Security, Inc.
#

# The non-credentialed check only works against Windows 2000

include("compat.inc");

if (description)
{
 script_id(29314);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2016/11/28 21:52:57 $");

 script_cve_id("CVE-2007-3039");
 script_bugtraq_id(26797);
 script_osvdb_id(39123);
 script_xref(name:"TRA", value:"TRA-2007-11");
 script_xref(name:"MSFT", value:"MS07-065");

 script_name(english:"MS07-065: Vulnerability in Message Queuing Could Allow Remote Code Execution (937894) (uncredentialed check)");
 script_summary(english:"Determines if hotfix 937894 has been installed (remote check)");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows is affected by a vulnerability in the
Microsoft Message Queuing Service (MSMQ).

An attacker may exploit this flaw to execute arbitrary code on the
remote host with SYSTEM privileges.");
 script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2007-11");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-065");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 2000 and XP.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS07-065 Microsoft Message Queueing Service DNS Name Path Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/12/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/12");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:message_queuing");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("smb_nativelanman.nasl");
 script_require_keys("Host/OS/smb");
 script_require_ports(2103);
 exit(0);
}

#

include ('smb_func.inc');

os = get_kb_item("Host/OS/smb");
if ( "Windows 5.0" >!< os ) exit (0);

port = 2103;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp (port);
if (!soc) exit (0);

host_ip = get_host_ip();

ret = dce_rpc_bind(cid:session_get_cid(), uuid:"41208ee0-e970-11d1-9b9e-00e02c064c39", vers:1);
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

session_set_unicode(unicode:1);
name = class_name(name:"nessus");

data =
     raw_word(w:3) +
     raw_word(w:3) +
     raw_dword(d:0) +
     name;

ret = dce_rpc_request (code:0x01, data:data);
send (socket:soc, data:ret);
resp = recv (socket:soc, length:4096);

close (soc);

resp = dce_rpc_parse_response (data:resp);
if (strlen(resp) != 4)
  exit (0);

# patched = 0xC00E0006
# not patched = 0xC00E0025

val = get_dword (blob:resp, pos:strlen(resp)-4);
if (val == 0xC00E0025)
  security_hole(port);
