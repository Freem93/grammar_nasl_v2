#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25707);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2011/06/11 00:23:27 $");

 script_cve_id("CVE-2007-3509");
 script_bugtraq_id (23897);
 script_osvdb_id(36111);

 script_name(english:"Symantec Backup Exec for Windows RPC Crafted ncacn_ip_tcp Request Remote Overflow");
 script_summary(english:"Test the VERITAS Backup Exec RPC Server heap overflow");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of VERITAS Backup Windows RPC server
which is vulnerable to a remote buffer overflow. An attacker may exploit this
flaw to execute arbitrary code on the remote host or to disable this service
remotely.

To exploit this flaw, an attacker would need to send a specially crafted packet
to the remote service.");
 script_set_attribute(attribute:"solution", value:
"http://seer.entsupport.symantec.com/docs/289731.htm");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/12");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/07/11");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/16");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:veritas_backup_exec");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("smb_nativelanman.nasl");
 script_require_keys("Host/OS/smb");
 script_require_ports(139,445);
 exit(0);
}


include ('smb_func.inc');

os = get_kb_item("Host/OS/smb");
if ( "Windows" >!< os ) exit (0);

port = 6106;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp (port);
if (!soc) exit (0);

ret = dce_rpc_bind(cid:session_get_cid(), uuid:"ebf5b2bb-09ab-415e-b89e-eb67c265f669", vers:1);
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


 data = raw_dword (d:4) +
	raw_dword (d:4) +
	raw_dword (d:4) +
	raw_dword (d:4);

ret = dce_rpc_request (code:0x00, data:data);
send (socket:soc, data:ret);
resp = recv (socket:soc, length:4096);

close (soc);

resp = dce_rpc_parse_response (data:resp);
if (strlen(resp) != 32)
  exit (0);

# patched = 0x000007c0 (11.0 -> ACCESS DENIED)
# not patched = 0x0000000e

val = get_dword (blob:resp, pos:strlen(resp)-4);
if (val == 0x0e)
  security_hole(port);

