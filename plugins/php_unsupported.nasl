#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58987);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/01/05 17:17:16 $");

  script_name(english:"PHP Unsupported Version Detection");
  script_summary(english:"Performs a version check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of a web application
scripting language.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of PHP on the remote host
is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/eol.php");
  script_set_attribute(attribute:"see_also", value:"https://wiki.php.net/rfc/releaseprocess");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of PHP that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

if (isnull(version)) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "PHP", port);

# http://php.net/eol.php as ref
eos_dates = make_array(
  "^5\.5($|\.)"  , '2016/07/21',
  "^5\.4($|\.)"  , '2015/09/14',
  "^5\.3($|\.)"  , '2014/08/14',
  "^5\.2($|\.)"  , '2011/01/06',
  "^5\.1($|\.)"  , '2006/08/24',
  "^5\.0($|\.)"  , '2005/09/05',
  "^4\.4($|\.)"  , '2008/08/07',
  "^4\.3($|\.)"  , '2005/03/31',
  "^4\.2($|\.)"  , '2002/09/06',
  "^4\.1($|\.)"  , '2002/03/12',
  "^4\.0($|\.)"  , '2001/06/23',
  "^3($|\.)"     , '2000/10/20',
  "^[0-2]($|\.)" , '2000/10/20'
);

withdrawl_announcements = make_array(
  "^5\.5($|\.)"  , 'http://php.net/supported-versions.php',
  "^5\.4($|\.)"  , 'http://php.net/supported-versions.php',
  "^5\.3($|\.)"  , 'http://php.net/archive/2014.php#id2014-08-14-1',
  "^5\.2($|\.)"  , 'http://php.net/eol.php',
  "^5\.1($|\.)"  , 'http://php.net/eol.php',
  "^5\.0($|\.)"  , 'http://php.net/eol.php',
  "^4\.4($|\.)"  , 'http://php.net/eol.php',
  "^4\.3($|\.)"  , 'http://php.net/eol.php',
  "^4\.2($|\.)"  , 'http://php.net/eol.php',
  "^4\.1($|\.)"  , 'http://php.net/eol.php',
  "^4\.0($|\.)"  , 'http://php.net/eol.php',
  "^3($|\.)"     , 'http://php.net/eol.php',
  "^[0-2]($|\.)" , 'http://php.net/eol.php'
);

supported_versions = '7.1.x / 7.0.x / 5.6.x';

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);
version_highlevel = strcat(ver[0], ".", ver[1]);

# Determine support status.
obsolete = '';
foreach v (keys(eos_dates))
{
  if (version_highlevel =~ v)
  {
    obsolete = v;
    break;
  }
}

if (obsolete)
{
  register_unsupported_product(product_name:"PHP",
                               cpe_base:"php:php", version:version);

  if (report_verbosity > 0)
  {
    info =
      '\n  Source              : ' + source  +
      '\n  Installed version   : ' + version;

    if (eos_dates[v])
      info += '\n  End of support date : ' + eos_dates[v];
    if (withdrawl_announcements[v])
      info += '\n  Announcement        : ' + withdrawl_announcements[v];
    info += '\n  Supported versions  : ' + supported_versions + '\n';

    security_hole(port:port, extra:info);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
