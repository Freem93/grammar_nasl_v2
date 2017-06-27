#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45359);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id("CVE-2010-0433", "CVE-2010-0740");
  script_bugtraq_id(38533, 39013);
  script_osvdb_id(62719, 63299);
  script_xref(name:"Secunia", value:"38807");

  script_name(english:"OpenSSL < 0.9.8n Multiple Vulnerabilities");
  script_summary(english:"Does a banner check");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server has multiple SSL-related vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote web server is running a version
of OpenSSL older than 0.9.8n.  Such versions have the following
vulnerabilities :

  - Kerberos-enabled versions of OpenSSL do not check
    the return value when Kerberos configuration files
    cannot be opened, leading to a crash. (CVE-2010-0433)

  - Rejecting a SSL/TLS record with an incorrect version
    number can lead to a crash.  This only affects version
    0.9.8m if a 'short' is 16 bits.  Otherwise, it affects 
    all versions back to and including 0.9.8f. 
    (CVE-2010-0740)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openwall.com/lists/oss-security/2010/03/03/5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/news/secadv/20100324.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openssl.org/news/changelog.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSL 0.9.8n or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/03/24");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/03/24");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/03/26");
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

if (version =~ "^0\.9\.([0-7]|8([^a-z0-9]|[a-m]|$))")
{
  if (report_verbosity > 0)
  {
    report =
      '\nOpenSSL version '+version+' appears to be running on the remote\n'+
      'host based on the following Server response header :\n\n'+
      '  '+line+'\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, 'The web server on port "+port+" uses OpenSSL '+version+', which is not affected.');
