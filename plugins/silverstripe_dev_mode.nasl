#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44940);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/21 20:34:21 $");

  script_name(english:"SilverStripe CMS Running in Development Mode");
  script_summary(english:"Checks if SilverStripe is running in development mode.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a PHP application that appears to be
running in a development mode.");
  script_set_attribute(attribute:"description", value:
"The SilverStripe CMS install hosted on the remote web server appears
to be running in development mode.

When running in development mode, debugging tools are accessible without
authentication, which could enable an attacker to gain sensitive
information relating to the application.");
  script_set_attribute(attribute:"see_also", value:"http://doc.silverstripe.org/doku.php?id=debugging");
  script_set_attribute(attribute:"solution", value:
"If this is a production system, consider putting SilverStripe in live
mode by adding the following line to the 'mysite/_config.php' file :

  Director::set_environment_type("+'"'+"live"+'"'+");");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:silverstripe:silverstripe");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("silverstripe_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/silverstripe");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php: 1);

install = get_install_from_kb(appname:'silverstripe', port:port);
if (isnull(install)) exit(1, "SilverStripe CMS wasn't detected on port "+port+".");

# Determine if the system is in Dev mode.
res = http_send_recv3(method:"GET", item:install['dir']+'/dev', port:port, exit_on_fail: 1);

if (
  res[2] &&
  '<title>GET '+install['dir']+'/dev' >< res[2] &&
  '<h1>Sapphire Development Tools</h1>' >< res[2] &&
  'Build/rebuild this environment' >< res[2]
)
{
  set_kb_item(name:'www/silverstripe'+install['dir']+'/dev', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to verify SilverStripe is running in development mode\n'+
      'with the following request :\n' +
      '\n' +
      crap(data:"-", length:30) + ' snip ' + crap(data:"-", length:30) + '\n' +
      '  ' + build_url(port:port, qs:install['dir']+'/dev') + '\n' +
      crap(data:"-", length:30) + ' snip ' + crap(data:"-", length:30) + '\n';
    if (report_verbosity > 1)
    {
      output = strstr(res[2], "Sapphire Development Tools") - res[2];
      report =
        report +
        'It produced the following output : \n' +
        crap(data:"-", length:30) + ' snip ' + crap(data:"-", length:30) + '\n' +
        output + '\n' +
        crap(data:"-", length:30) + ' snip ' + crap(data:"-", length:30) + '\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
  exit(0);
}
else exit(0, "The SilverStripe install at "+build_url(port:port, qs:install['dir'])+" is not running in development mode.");
