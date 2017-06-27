#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87538);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/23 14:38:50 $");

  script_cve_id("CVE-2015-2808");
  script_bugtraq_id(73684);
  script_osvdb_id(117855);

  script_name(english:"IBM HTTP Server SSL/TLS RC4 Stream Cipher Key Invariance (Bar Mitzvah)");
  script_summary(english:"Checks the version in server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a security feature bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of IBM HTTP Server running on the
remote host is affected by a security feature bypass vulnerability,
known as Bar Mitzvah, due to improper combination of state data with
key data by the RC4 cipher algorithm during the initialization phase.
A man-in-the-middle attacker can exploit this, via a brute-force
attack using LSB values, to decrypt the traffic.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21701072");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24039770");
  # https://www.blackhat.com/docs/asia-15/materials/asia-15-Mantin-Bar-Mitzvah-Attack-Breaking-SSL-With-13-Year-Old-RC4-Weakness-wp.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bbf45ac");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM HTTP Server 7.0.0.39 / 8.0.0.11 / or 8.5.5.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:http_server");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("www/ibm-http", "Settings/ParanoidReport");
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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Get Server header and version
pattern = "IBM[ _]HTTP[ _]Server\/(V([0-9]+)R([0-9]+)M([0-9]+))";
matches = eregmatch(pattern:pattern, string:server_header);
if (!isnull(matches))
{
  version = matches[2] + "." + matches[3] + "." + matches[4];
}
else
{
  pattern = "IBM[ _]HTTP[ _]Server\/([0-9]+[0-9.]+)";
  matches = eregmatch(pattern:pattern, string:server_header);
  version = matches[1];
}

if (isnull(matches)) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "IBM HTTP Server", port);

# Check granularity
# format V#R#M# versions are going to be
# not granular enough by default in this case.
if (
  # All of 6.0 and 6.1 can be configured in a vulnerable state
  version =~ "^7(\.0)?$" ||
  version =~ "^7\.0\.0$" ||
  version =~ "^8(\.0)?$" ||
  version =~ "^8\.0\.0$" ||
  version =~ "^8\.5(\.5)?$"
) audit(AUDIT_VER_NOT_GRANULAR, "IBM HTTP Server", port, version);

source = matches[0];

fix = FALSE;
if (version =~ "^6\.[0-1]\.")
{
  # 6.0 and 6.1 do not have patches, but they do have RC4 enabled by default.
  # RC4 can be removed by enabling FIPS140-2, or by following a walk through.
  fix = "See vendor";
}
else if (version =~ "^7\.0\.0\.([0-9]|[1-2][0-9]|3[0-7])($|[^0-9])")
{
  # V7.0.0.0 through 7.0.0.37
  fix = "7.0.0.39";
}
else if (version =~ "^8\.0\.0\.([0-9]|10)($|[^0-9])")
{
  # V8.0 through 8.0.0.10
  fix = "8.0.0.11";
}
else if (version =~ "^8\.5\.[0-4]($|[^0-9])" ||
         version =~ "^8\.5\.5\.[0-5]($|[^0-9])")
{
  # V8.5.0.0 through 8.5.4.x
  # V8.5.5.0 through 8.5.5.5
  fix = "8.5.5.6";
}

if (fix)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "IBM HTTP Server", port, version);
