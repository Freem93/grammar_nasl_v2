#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66760);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/24 02:15:09 $");

  script_cve_id("CVE-2012-5955");
  script_bugtraq_id(57010);
  script_osvdb_id(88624);
  script_xref(name:"IAVA", value:"2013-A-0020");

  script_name(english:"IBM HTTP Server for z/OS 5.3.0 Command Execution");
  script_summary(english:"Checks version in Server response header");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by a command execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of IBM HTTP Server on the
remote host is version 5.3.0. It is, therefore, potentially affected
by an unspecified command execution vulnerability. This issue only
affects IBM HTTP Server for z/OS.

Note that Nessus did not actually test for this issue, but instead
has relied on the version in the server's banner.

Further note that Nessus has not attempted to determine if the 'PTF
UK90469' patch or a later patch has been applied.  If a patch has
already been applied, consider this a false positive.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?&uid=swg21620945");
  script_set_attribute(attribute:"solution", value:
"Apply PTF UK90469 or later which includes APAR PM79239.

Note that if the recommended patch or a subsequent patch has been
installed, this can be considered a false positive and no action is
required.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:http_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/ibm-http", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("http_misc_func.inc");

get_kb_item_or_exit("www/ibm-http");

port = get_http_port(default:80);

# Get Server header
server_header = http_server_header(port:port);
if (isnull(server_header)) exit(0, 'The web server on port '+port+' does not include a Server response header in its banner.');

# Make sure this is IBM HTTP
if ("IBM HTTP Server" >!< server_header) audit(AUDIT_WRONG_WEB_SERVER, port, "IBM HTTP Server for z/OS");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Get Server header and version
pattern = "IBM HTTP Server\/(V([0-9]+)R([0-9]+)M([0-9]+))";
matches = eregmatch(pattern:pattern, string:server_header);
if (isnull(matches)) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "IBM HTTP Server for z/OS", port);

source = matches[0];

# Build the version, e.g.:
# raw_version: V5R3M0
# version: 5.3.0
version = matches[2] + "." + matches[3] + "." + matches[4];

if (version == "5.3.0")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : See Solution' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "IBM HTTP Server for z/OS", port, version);
