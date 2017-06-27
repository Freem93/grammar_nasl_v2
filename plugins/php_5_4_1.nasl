#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58967);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/11/14 12:03:07 $");

  script_cve_id("CVE-2012-1172", "CVE-2012-4388");
  script_bugtraq_id(53403, 55527);
  script_osvdb_id(81791, 85086);

  script_name(english:"PHP 5.4.x < 5.4.1 Multiple Vulnerabilities");
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
host is 5.4.x earlier than 5.4.1, and, therefore, potentially affected
by multiple vulnerabilities :

  - The '$_FILES' variable can be corrupted because the
    names of uploaded files are not properly validated.
    (CVE-2012-1172)

  - The 'open_basedir' directive is not properly handled by
    the functions 'readline_write_history' and
    'readline_read_history'.

  - It's possible to bypass an HTTP response-splitting
    protection because the 'sapi_header_op()' function in 
    main/SAPI.c does not properly determine a pointer during
    checks for encoded carriage return characters. (Bug 
    #60227 / CVE-2012-4388)"
  );
  # https://nealpoole.com/blog/2011/10/directory-traversal-via-php-multi-file-uploads/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e81d4026");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=54374");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=60227");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/archive/2012.php#id2012-04-26-1");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.4.1");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

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

if (version =~ "^5\.4\.0($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.4.1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
