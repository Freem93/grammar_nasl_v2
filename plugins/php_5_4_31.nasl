#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76791);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/07/25 20:40:01 $");

  script_osvdb_id(109535);

  script_name(english:"PHP 5.4.x < 5.4.31 CLI Server 'header' DoS");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP 5.4.x in use on the remote
web server is a version prior to 5.4.31. It is, therefore, affected by
a denial of service vulnerability that affects the built-in command
line development server.

The function 'sapi_cli_server_send_headers' in the file
'sapi/cli/php_cli_server.c' contains an error that does not properly
handle an empty 'header' parameter and could allow denial of service
attacks.

Note that this issue affects only the built-in command line
development server.

Further note that Nessus has not attempted to exploit this issue, but
has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.4.31");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=66830");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.4.31 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
php = get_php_from_kb(port:port, exit_on_fail:TRUE);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# Check that it is the correct version of PHP
if (version =~ "^5(\.4)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.4\.") audit(AUDIT_NOT_DETECT, "PHP version 5.4.x", port);

if (version =~ "^5\.4\.([0-9]|[12][0-9]|30)($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source +
      '\n  Installed version : '+version+
      '\n  Fixed version     : 5.4.31\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
