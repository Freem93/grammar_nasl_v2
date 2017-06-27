#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84290);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/16 14:02:51 $");

  script_cve_id("CVE-2015-1829");
  script_bugtraq_id(75164);
  script_osvdb_id(121515);

  script_name(english:"IBM HTTP Server on Windows Apache Portable Runtime (APR) Named Pipe DoS");
  script_summary(english:"Checks the version in server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of IBM HTTP Server running on the
remote host is potentially affected by a denial of service
vulnerability due to an error related to the included Apache Portable
Runtime (APR) and named pipe handling. A local attacker, using a
'named pipe squatting attack' from a local process, can exploit this
to cause a denial of service. This issue only affects IBM HTTP Server
on Windows.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.

Also note that Nessus has not attempted to determine if the 'PI39833'
interim fix or a later patch has been applied. If a patch has already
been applied, consider this a false positive.");
  # Security bulletin
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21959081");
  # Interim fix
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24040155");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 6.0.2.43, 6.1.0.47, 7.0.0.37, 8.0.0.9, or 8.5.5.5. Then
apply Interim Fix PI39833.

Note that the fix is scheduled to be included in the following
versions :

  - 7.0.0.39 
  - 8.0.0.11 
  - 8.5.5.7");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl");
  script_require_keys("www/ibm-http", "Settings/ParanoidReport", "Host/OS");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

get_kb_item_or_exit("www/ibm-http");

port = get_http_port(default:80);

# Get Server header
server_header = http_server_header(port:port);
if (empty_or_null(server_header)) audit(AUDIT_WEB_NO_SERVER_HEADER, port);

# Make sure this is IBM HTTP
if (
  "IBM HTTP Server" >!< server_header &&
  "IBM_HTTP_Server" >!< server_header
) audit(AUDIT_WRONG_WEB_SERVER, port, "IBM HTTP Server");

# Make sure this is Windows
os = get_kb_item_or_exit("Host/OS");
if ("windows" >!< tolower(os)) audit(AUDIT_OS_NOT, "Windows", os);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Get Server header and version
pattern = "IBM[ _]HTTP[ _]Server\/(V([0-9]+)R([0-9]+)M([0-9]+))";
matches = eregmatch(pattern:pattern, string:server_header);
if (!isnull(matches))
{
  # Build the version, e.g.:
  # raw_version: V5R3M0
  # version: 5.3.0
  version = matches[2] + "." + matches[3] + "." + matches[4];
}
else
{
  pattern = "IBM[ _]HTTP[ _]Server\/([0-9]+[0-9.]+)";
  matches = eregmatch(pattern:pattern, string:server_header);
  version = matches[1];
}

if (isnull(matches)) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "IBM HTTP Server for Windows", port);

# Check granularity
# format V#R#M# versions are going to be
# not granular enough by default in this case.
if (
  version =~ "^6(\.0)?$" ||
  version =~ "^6\.0\.2$" ||
  version =~ "^6\.1(\.0)?$" ||
  version =~ "^7(\.0)?$" ||
  version =~ "^7\.0\.0$" ||
  version =~ "^8(\.0)?$" ||
  version =~ "^8\.0\.0$" ||
  version =~ "^8\.5(\.5)?$"
) audit(AUDIT_VER_NOT_GRANULAR, "IBM HTTP Server", port, version);

source = matches[0];

if (
  # V6.0.0.0 through 6.0.1.x
  version =~ "^6\.0\.[01]($|[^0-9])" ||
  # V6.0.2.0 through 6.0.2.43
  version =~ "^6\.0\.2\.([0-9]|[1-3][0-9]|4[0-3])($|[^0-9])" ||
  # V6.1.0.0 through 6.1.0.47
  version =~ "^6\.1\.0\.([0-9]|[1-3][0-9]|4[0-7)($|[^0-9])"     ||
  # V7.0.0.0 through 7.0.0.37 (with 7.0.0.38)
  version =~ "^7\.0\.0\.([0-9]|[1-2][0-9]|3[0-8])($|[^0-9])" ||
  # V8.0 through 8.0.0.10
  version =~ "^8\.0\.0\.([0-9]|10)($|[^0-9])" ||
  # V8.5.0.0 through 8.5.4.x
  version =~ "^8\.5\.[0-4]($|[^0-9])" ||
  # V8.5.5.0 through 8.5.5.5 (with 8.5.5.6)
  version =~ "^8\.5\.5\.[0-6]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : See solution' +
      '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "IBM HTTP Server for Windows", port, version);
