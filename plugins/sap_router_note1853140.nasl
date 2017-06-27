#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72263);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_cve_id("CVE-2013-7093");
  script_bugtraq_id(64230);
  script_osvdb_id(100952);

  script_name(english:"SAProuter Remote Authentication Bypass (Note 1853140)");
  script_summary(english:"Attempts to request information from SAProuter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is susceptible to an authentication bypass
attack.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of SAProuter that is affected by an
authentication bypass vulnerability. When started with the '-X' flag,
SAProuter permits routing to itself given a 'saprouttab' that allows
access to its port. An unauthenticated, remote attacker can issue
commands to SAProuter.");

  script_set_attribute(attribute:"see_also", value:"https://service.sap.com/sap/support/notes/1853140");
  # http://erpscan.com/advisories/erpscan-13-023-saprouter-authentication-bypass/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2f0812eb");

  script_set_attribute(attribute:"solution", value:
"Restart SAProuter without '-X' and review the permissions in
'saprouttab'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/03");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:sap:network_interface_router");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("sap_router_detect.nbin");
  script_require_keys("Services/sap_router");

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

# Find the port from the KB.
port = get_service(svc:"sap_router", default:3299, exit_on_fail:TRUE);

# Pull the version from the KB.
ver = get_kb_item_or_exit("sap/router/" + port + "/ver");
if (ver !~ "^[0-9]+(\.[0-9]+( \(SP[0-9]+\))?)*$") audit(AUDIT_NONNUMERIC_VER, "SAProuter", port, ver);
ver = split(ver, sep:".", keep:FALSE);
ver = int(ver[0]);

if( ver !~ "^39\." && ver !~ "^40\.")
  audit(AUDIT_LISTEN_NOT_VULN, "SAProuter", port, ver);

# Open a socket.
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

# All parameters are big-endian.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Create a request packet for a '-l' (router info).
req = raw_string(
  0, 0, 0, 15,    # Length of body
  'ROUTER_ADM\0', # Request type (admin)
  ver,            # Client major version
  2,              # Opcode (info request)
  0, 0            # Padding
);

# Send the request.
send(socket:soc, data:req);

# The response will be some number of length-prefixed messages,
# containing either ASCII or binary lines. We don't know the full
# packet format, so a useful heuristic is that when we're successful,
# we'll get multiple responses many of which are null-terminated
# strings.
#
# The final message is empty, just a dword of null bytes for length.
info = "";
while (TRUE)
{
  # Get the length of the response.
  res = recv(socket:soc, min:4, length:4);
  len = getdword(blob:res);
  if (!len)
    break;

  # Get the body of the response.
  res = recv(socket:soc, min:len, length:len);
  if (strlen(res) != len)
    break;

  # Check for an error.
  if ("NI_RTERR" >< res)
  {
    info = "";
    break;
  }

  # If the response contains only printable characters and is
  # null-terminated, then keep it.
  res = str_replace(string:res, find:'\n', replace:'');
  if (res =~ "^[\x20-\x7E]+.$")
    info += '\n  ' + substr(res, 0, strlen(res) - 2);
}

close(soc);

if (!info) audit(AUDIT_LISTEN_NOT_VULN, "SAProuter", port);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus was able to retrieve the following information from the'+
    '\n' + 'remote SAProuter by issuing an information request :' +
    '\n' +  info +
    '\n';
}

security_warning(port:port, extra:report);
