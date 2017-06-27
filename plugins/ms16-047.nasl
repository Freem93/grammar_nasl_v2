#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(90510);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/07/19 18:40:13 $");

  script_cve_id("CVE-2016-0128");
  script_bugtraq_id(86002);
  script_osvdb_id(136339);
  script_xref(name:"MSFT", value:"MS16-047");
  script_xref(name:"CERT", value:"813296");
  script_xref(name:"IAVA", value:"2016-A-0093");

  script_name(english:"MS16-047: Security Update for SAM and LSAD Remote Protocols (3148527) (Badlock) (uncredentialed check)");
  script_summary(english:"Checks response from SAM RPC service.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability in the Security Account Manager (SAM) and Local Security
Authority (Domain Policy) (LSAD) protocols due to improper
authentication level negotiation over Remote Procedure Call (RPC)
channels. A man-in-the-middle attacker able to intercept
communications between a client and a server hosting a SAM database
can exploit this to force the authentication level to downgrade,
allowing the attacker to impersonate an authenticated user and access
the SAM database.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-047");
  script_set_attribute(attribute:"see_also", value:"http://badlock.org/");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("dcetest.nasl", "os_fingerprint.nasl");
  script_require_keys("Services/DCE/12345778-1234-abcd-ef00-0123456789ac");

  exit(0);
}

include("smb_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("audit.inc");

os = get_kb_item_or_exit("Host/OS");
if("Windows" >!< os) audit(AUDIT_OS_NOT, "Windows");

rpc = 'SAM'; uuid = '12345778-1234-abcd-ef00-0123456789ac'; vers = 1; 

# Get the dynamic TCP port for SAMR
port = get_kb_item('Services/DCE/' + uuid);
if(! port)
  exit(0, 'Failed to get the dynamic TCP port for RPC service ' + rpc + '.');

if (! get_port_state(port)) 
  audit(AUDIT_PORT_CLOSED, port);
  
soc = open_sock_tcp(port);
if( ! soc)
  audit(AUDIT_SOCK_FAIL, port);

#
# We use RPC over TCP:
#  
# Connect with NULL credentials
ret = dce_rpc_connect (socket: soc, cid: session_get_cid(), uuid:uuid, 
                       vers: vers, login:NULL, password:NULL, domain:NULL);

if(isnull(ret))
  exit(1, 'Failed to connect to RPC port '+port+'.');
 

data = class_parameter (ref_id:0x00020000, name:"\"+session_get_hostname()) +
        raw_dword (d:0x30)        ; # Access mask

req = dce_rpc_request (code:OPNUM_SAMCONNECT2, data:data);
send(socket:soc, data:req);
res = recv(socket:soc, length:4096);
if(isnull(res))
  audit(AUDIT_RESP_NOT, port, 'a RPC request');

rlen = strlen(res);
if(rlen < 24)
  audit(AUDIT_RESP_BAD, port, 'an RPC request: invalid response size');

type = get_byte(blob:res, pos:2);

# Response 
if(type == 2)
{
  if(rlen >= 24 + 24)
  {
    # NT status
    status = getdword(blob:res, pos:44,order:BYTE_ORDER_LITTLE_ENDIAN);
    if(status == STATUS_SUCCESS || status == STATUS_ACCESS_DENIED)
      security_warning(port:port);
    else
      audit(AUDIT_RESP_BAD, port, 'an RPC request: unexpected response status ' + status);
  }
  else
    exit(1, 'Failed to get response status.'); 
  
}
# Fault
else if(type == 3)
{
  if(rlen >= 24 + 4)
  {
    status = getdword(blob:res, pos:24,order:BYTE_ORDER_LITTLE_ENDIAN);

    # nca_s_fault_access_denied could mean
    # 1) anonymous login fails (AUTH3 failed)
    # 2) remote host is patched
    if(status == ERROR_ACCESS_DENIED)
      exit(0, 'The remote host is not affected or anonymous login failed.');  
    else
      audit(AUDIT_RESP_BAD, port, 'an RPC request: unexpected fault status '+ status);
  }
  else
    exit(1, 'Failed to get fault status.'); 

}
# Unexpected packet type
else
{
  audit(AUDIT_RESP_BAD, port, 'an RPC request: unexpected return packet type ' + type);
}
