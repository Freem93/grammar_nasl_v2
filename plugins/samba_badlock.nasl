#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90509);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/07/25 14:52:53 $");

  script_cve_id("CVE-2016-2118");
  script_bugtraq_id(86002);
  script_osvdb_id(136339);
  script_xref(name:"CERT", value:"813296");

  script_name(english:"Samba Badlock Vulnerability");
  script_summary(english:"Detects if the Badlock patch has been applied.");

  script_set_attribute(attribute:"synopsis", value:
"An SMB server running on the remote host is affected by the Badlock
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Samba, a CIFS/SMB server for Linux and Unix, running on
the remote host is affected by a flaw, known as Badlock, that exists
in the Security Account Manager (SAM) and Local Security
Authority (Domain Policy) (LSAD) protocols due to improper
authentication level negotiation over Remote Procedure Call (RPC)
channels. A man-in-the-middle attacker who is able to able to
intercept the traffic between a client and a server hosting a SAM
database can exploit this flaw to force a downgrade of the
authentication level, which allows the execution of arbitrary Samba
network calls in the context of the intercepted user, such as viewing
or modifying sensitive security data in the Active Directory (AD)
database or disabling critical services.");
  script_set_attribute(attribute:"see_also", value:"http://badlock.org");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2016-2118.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.2.11 / 4.3.8 / 4.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
 
  script_dependencies("samba_detect.nasl");
  script_require_ports(139, 445);
  script_require_keys("SMB/samba", "SMB/name", "SMB/transport");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("misc_func.inc");
include("global_settings.inc");

# DCERPC reject status codes
PROTO_ERROR = 0x1c01000b;
RING_ERROR = 0x1c010002;

appname = "Samba";
get_kb_item_or_exit("SMB/samba");
name = kb_smb_name();
port = kb_smb_transport();

###
# Binds to one of the typically available pipes
# @return a fd to the pipe
##
function bind_to_pipe()
{
  local_var fid = bind_pipe (pipe:"\unixinfo", uuid:"9c54e310-a955-4885-bd31-78787147dfa6", vers:0);
  if (!isnull(fid)) return fid;

  fid = bind_pipe (pipe:"\spoolss", uuid:"12345678-1234-abcd-ef00-0123456789ab", vers:1);
  if (!isnull(fid)) return fid;

  fid = bind_pipe (pipe:"\lsarpc", uuid:"12345778-1234-abcd-ef00-0123456789ab", vers:0);
  if (!isnull(fid)) return fid;

  # if samba_detect.nasl is successful than we should never be able to
  # hit here since we know it successfully bound to a pipe.
  audit(AUDIT_RESP_BAD, port);
}

if (get_kb_item("Host/scanned") && !get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

# establish a connection
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

# start the session and try to connect to the share
session_init(socket:soc, hostname:name);
if (NetUseAdd(share:"IPC$") != 1) audit(AUDIT_SHARE_FAIL, "IPC");

# We need to bind to a pipe. We know samba_detect did so try
# the known pipes
bound_pipe = bind_to_pipe();

# Make a ping request (this should be unexpected)
data = raw_word(w:0);
data = dce_rpc_pipe_request(fid:bound_pipe, code:0x3f, data:data, type:1);
smb_close (fid:bound_pipe);
NetUseDel();

if (!data || (strlen(data) < 28)) audit(AUDIT_RESP_BAD, port, "the RPC pipe request");
   
# Type should be fault (3)
if (get_byte (blob:data, pos:2) != 3) audit(AUDIT_RESP_BAD, port, "the type examination");

# Check against the two known errors; any third type will be flagged as a bad resp.
error = get_dword (blob:data, pos:24);
if (error == PROTO_ERROR) audit(AUDIT_INST_VER_NOT_VULN, appname);
else if (error != RING_ERROR) audit(AUDIT_RESP_BAD, port, "the error code check");

report = '\nNessus detected that the Samba Badlock patch has not been applied.\n';
security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
