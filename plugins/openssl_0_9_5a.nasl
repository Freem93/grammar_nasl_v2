#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17707);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/02 14:37:07 $");

  script_cve_id("CVE-2000-0535");
  script_bugtraq_id(1340);
  script_osvdb_id(3938);

  script_name(english:"OpenSSL < 0.9.5a /dev/random Check Failure");
  script_summary(english:"Checks the version of OpenSSL");

  script_set_attribute(attribute:"synopsis", value:
"The remote host uses a version of OpenSSL that may have weak
encryption keys.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSL running on the remote
host is less than 0.9.5a. On a FreeBSD system running on the Alpha
architecture, versions earlier than that may not use the /dev/random
and /dev/urandom devices to provide a strong source of cryptographic
entropy, which could lead to the generation of keys with weak
cryptographic strength.");
  script_set_attribute(attribute:"see_also", value:"http://cvs.openssl.org/fileview?f=openssl/CHANGES&v=1.514");
  # https://web.archive.org/web/20000819114726/http://archives.neohapsis.com/archives/freebsd/2000-06/0083.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16bc8320");
  script_set_attribute(attribute:"solution", value:
"Upgrade OpenSSL to version 0.9.5a or higher and re-generate encryption
keys.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
banner = get_backport_banner(banner:get_http_banner(port:port));
if (!banner) exit(1, "Unable to get the banner from web server on port "+port+".");

if (!egrep(string:banner, pattern:'^Server:'))
  exit(1, "The web server on port "+port+" doesn't return a Server response header.");
if ("OpenSSL/" >!< banner)
  exit(1, "The Server response header for the web server on port "+port+" doesn't mention OpenSSL.");

pat = "^Server:.*OpenSSL/([^ ]+)";
version = "";

foreach line (split(banner, sep:'\r\n', keep:FALSE))
{
  match = eregmatch(pattern:pat, string:line);
  if (!isnull(match))
  {
    version = match[1];
    break;
  }
}
if (isnull(version)) exit(0, "Failed to extract the version of OpenSSL used by the web server on port "+port+".");

# Anything less than 0.9.5a.
if (version =~ "^0\.9\.([0-4]|5([^a-z0-9]|$))")
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
else exit(0, 'The web server on port ' +port+ ' uses OpenSSL '+version+', which is not affected.');
