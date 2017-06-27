#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51919);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/09/01 13:42:18 $");

  script_cve_id("CVE-2011-0014");
  script_bugtraq_id(46264);
  script_osvdb_id(70847);
  script_xref(name:"Secunia", value:"43227");

  script_name(english:"OpenSSL OCSP Stapling Denial of Service");
  script_summary(english:"Does a banner check.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server has an SSL-related denial of service
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote web server is running a version
of OpenSSL older than 0.9.8r or 1.0.0d. 

Incorrectly formatted ClientHello handshake messages could cause
OpenSSL to parse past the end of the message.  This could cause the
web server to crash.  There is also the potential for information
disclosure if OCSP nonce extensions are used."
  );

  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/news/secadv/20110208.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cvs.openssl.org/chngview?cn=20359"
  );

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSL 0.9.8r / 1.0.0d or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date",value:"2011/02/08");
  script_set_attribute(attribute:"patch_publication_date",value:"2011/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/09");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2)
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

# Check if OpenSSL is used by the web server.
port = get_http_port(default:80);
banner = get_backport_banner(banner:get_http_banner(port:port, exit_on_fail:TRUE));
if (!egrep(string:banner, pattern:"^Server:"))
  exit(0, "The web server on port " + port + " doesn't return a Server response header.");
if ("OpenSSL/" >!< banner)
  exit(0, "The Server response header for the web server on port " + port + " doesn't mention OpenSSL.");


# Try to find the version string in the banner.
version = NULL;
pat = "^Server:.*OpenSSL/([^ ]+)";

foreach line (split(banner, sep:'\r\n', keep:FALSE))
{
  match = eregmatch(pattern:pat, string:line);
  if (!isnull(match))
  {
    version = match[1];
    break;
  }
}

if (isnull(version))
  exit(0, "Could not determine the version of OpenSSL used by the web server on port " + port + ".");

if (
  (version =~ "^0\.9\.8([^a-z0-9]|[h-q])") ||
  (version =~ "^1\.0\.0(-beta|[a-c]|$)")
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + line +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 0.9.8r / 1.0.0d\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The web server on port " + port + " uses OpenSSL " + version + ", which is not affected.");
