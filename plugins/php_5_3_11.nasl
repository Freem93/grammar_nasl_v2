#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58966);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/10/23 20:09:34 $");

  script_cve_id("CVE-2011-1398", "CVE-2012-0831", "CVE-2012-1172");
  script_bugtraq_id(51954, 53403, 55297);
  script_osvdb_id(79017, 81791, 85086);

  script_name(english:"PHP < 5.3.11 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is affected by 
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP installed on the remote
host is earlier than 5.3.11, and as such is potentially affected by
multiple vulnerabilities :

 - During the import of environment variables, temporary
   changes to the 'magic_quotes_gpc' directive are not
   handled properly. This can lower the difficulty for
   SQL injection attacks. (CVE-2012-0831)

 - The '$_FILES' variable can be corrupted because the
   names of uploaded files are not properly validated.
   (CVE-2012-1172)

 - The 'open_basedir' directive is not properly handled by
   the functions 'readline_write_history' and
   'readline_read_history'.

  - The 'header()' function does not detect multi-line
    headers with a CR. (Bug #60227 / CVE-2011-1398)"
  );
  # https://nealpoole.com/blog/2011/10/directory-traversal-via-php-multi-file-uploads/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e81d4026");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=61043");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=54374");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=60227");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=oss-security&m=134626481806571&w=2");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/archive/2012.php#id2012-04-26-1");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.3.11");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.3.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# All before 5.3.11 are affected.
fixed_version = '5.3.11';

if (
  version =~ "^[0-4]($|\.)" ||
  version =~ "^5\.[0-2]($|\.)" ||
  version =~ "^5\.3\.([0-9]|10)($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : '+fixed_version+'\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
