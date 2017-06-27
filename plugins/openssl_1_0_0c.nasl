#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51058);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id("CVE-2010-4180", "CVE-2010-4252");
  script_bugtraq_id(45163, 45164);
  script_osvdb_id(69565, 69657);
  script_xref(name:"Secunia", value:"42473");

  script_name(english:"OpenSSL < 0.9.8q / 1.0.0c Multiple Vulnerabilities");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote web server is running a version
of OpenSSL older than 0.9.8q or 1.0.0c.  Such versions are potentially
affected by multiple vulnerabilities :

  - It may be possible to downgrade the ciphersuite to a
    weaker version by modifying the stored session cache
    ciphersuite.

  - An error exists in the J-PAKE implementation that could
    lead to successful validation by someone with no 
    knowledge of the shared secret.");
  
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20101202.txt");
  script_set_attribute(attribute:"see_also", value:"http://seb.dbzteam.org/crypto/jpake-session-key-retrieval.pdf");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.8q / 1.0.0c or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/12/02");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/07");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("backport.inc");


if (report_paranoia < 2)
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

port = get_http_port(default:80);

banner = get_backport_banner(banner:get_http_banner(port:port));
if (!banner) 
  exit(1, "Unable to get the banner from the web server on port "+port+".");

if (!egrep(string:banner, pattern:'^Server:'))
  exit(0, "The web server on port "+port+" doesn't return a Server response header.");
if ("OpenSSL/" >!< banner)
  exit(0, "The Server response header for the web server on port "+port+" doesn't mention OpenSSL.");

pat = "^Server:.*OpenSSL/([^ ]+)";
version = NULL;

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
  exit(0, "The web server on port "+port+" doesn't appear to use OpenSSL.");

if (
  (version =~ "^0\.[0-8]\..*") ||
  (version =~ "^0\.9\.([0-7]([^0-9]|$)|8([^a-z0-9]|[a-p]|$))") ||
  (version =~ "^1\.0\.0(-beta|[a-b]|$)")
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + line +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 0.9.8q / 1.0.0c\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, 'The web server on port \''+port+'\' uses OpenSSL '+version+', which is not affected.');
