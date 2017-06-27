#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(45439);
  script_version("$Revision: 1.5 $");
 script_cvs_date("$Date: 2016/04/21 16:17:30 $");

  script_name(english:"Mac OS X Server Web Services Version Detection");
  script_summary(english:"Queries the version of Mac OS X Web Services");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is running Mac OS X Server Web Services.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Mac OS X Server Web Services, a set of
services for handling remote web services such as a wiki and a
calendar." );
  script_set_attribute(attribute:"solution", value:
"If you do not use these services, consider disabling the remote web
server." );
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

r = http_send_recv3(method:"GET", port:port, item:"/groups/", exit_on_fail:TRUE);

line = egrep(pattern:'<div class="page_footer_appversion"> *Mac OS X Server Web Services Server [0-9.]+</div>', string:r[2]);
if ( line )
{
 version = chomp(ereg_replace(pattern:'.*<div class="page_footer_appversion"> *Mac OS X Server Web Services Server ([0-9.]+)</div>.*', string:line, replace:"\1"));
}
else
{
 line = egrep(pattern:'<meta name="generator" content="Mac OS X Server Web Services Server [0-9.]+">', string:r[2]);
 if ( line )
   version = chomp(ereg_replace(pattern:'.*<meta name="generator" content="Mac OS X Server Web Services Server ([0-9.]+)">.*', string:line, replace:"\1"));
}
if ( ! version ) exit(0, 'Mac OS X Server Web Services Server is not running on port ' + port + '.');


e = add_install(appname  : "macosx_web_svcs_srv", port:port, dir:"/groups", ver:version);
report = get_install_report(
      port         : port,
      installs     : e,
      display_name : "Mac OS X Server Web Services");

security_note(port:port, extra:report);
