#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(11422);
  script_version("$Revision: 1.42 $");
  script_cvs_date("$Date: 2016/03/09 22:24:36 $");

  script_osvdb_id(3233);

  script_name(english:"Web Server Unconfigured - Default Install Page Present");
  script_summary(english:"Determines if the remote web server has been configured.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is not configured or is improperly configured.");
  script_set_attribute(attribute:"description", value:
"The remote web server uses its default welcome page. Therefore, it's
probable that this server is not used at all or is serving content
that is meant to be hidden.");
  script_set_attribute(attribute:"solution", value:
"Disable this service if you do not use it.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function report_def(port, srv)
{
  set_kb_item(name: "www/"+port+"/default_page", value: srv);
  security_report_v4(
    port     : port,
    severity : SECURITY_NOTE,
    extra    : '\nThe default welcome page is from ' + srv + '.\n'
  );
  exit(0);
}

port = get_http_port(default:80, dont_break: TRUE);
res = http_get_cache(item:"/", port:port, exit_on_fail: TRUE);
if (res =~ "^HTTP/[0-9.]+ 30[1237] " || empty_or_null(res))
{
 res = http_send_recv3(port: port, method: 'GET', item: '/', exit_on_fail: 1, follow_redirect:3);
 res = res[2];
}
res = tolower(res);

#
# Apache
#
apache_head = "<title>test page for apache installation</title>";
apache_body = "<p>this page is here because the site administrator has changed the
configuration of this web server. please <strong>contact the person
responsible for maintaining this server with questions.</strong>
the apache software foundation, which wrote the web server software
this site administrator is using, has nothing to do with
maintaining this site and cannot help resolve configuration
issues.</p>";

if(apache_head >< res && apache_body >< res) report_def(port:port, srv: "Apache");

apache_head = "<title>test page for the apache web server on red hat linux</title>";
apache_body = "this page is used to test the proper operation of the apache web server after";

if(apache_head >< res && apache_body >< res) report_def(port:port, srv: "Apache");


if(egrep(pattern:"<title>test page for .*apache installation on web site</title>",
         string:res))  report_def(port:port, srv: "Apache");


if("<title>test page for the apache http server on fedora core</title>" >< res)
 report_def(port:port, srv: "Apache");

#
# Apache Tomcat
#
tomcat_head = "<title>apache tomcat";
tomcat_body = "<(code|pre)>\$catalina_home/conf/tomcat-users\.xml</(code|pre)>";

if(tomcat_head >< res && res =~ tomcat_body) report_def(port:port, srv: "Tomcat");

#
# IIS 6.x
#
iis_head = "<title id=titletext>under construction</title>";
iis_body = "the site you were trying to reach does not currently have a default page. it may be in the process of being upgraded.";

if(iis_head >< res && iis_body >< res)
 report_def(port:port, srv: "IIS");

#
# IIS 7.0 / 7.5
#
iis7_head = '<title>iis7</title>';
iis7_body = '<img src="welcome.png" alt="iis7"';

if(iis7_head >< res && iis7_body >< res)
 report_def(port:port, srv: "IIS");

#
# IIS 8.0
#
iis8_head = '<title>microsoft internet information services 8</title>';
iis8_body= '<img src="iis-8.png" alt="microsoft internet information services 8.0"';

if (iis8_head >< res && iis8_body >< res)
 report_def(port:port, srv: "IIS");

#
# IIS 8.5
#
iis85_head = '<title>iis windows server</title>';
iis85_body = '<img src="iis-85.png" alt="iis"';

if (iis85_head >< res && iis85_body >< res)
 report_def(port:port, srv: "IIS");

# Chinese
iis_head = '<title id=titletext>\xD5\xFD\xD4\xDA\xBD\xA8\xC1\xA2</title>';
iis_body = '\xC4\xFA\xCF\xEB\xD2\xAA\xC1\xAC\xBD\xD3\xB5\xC4\xD5\xBE\xB5\xE3\xC4\xBF\xC7\xB0\xC3\xBB\xD3\xD0\xC4\xAC\xC8\xCF\xD2\xB3\xA1\xA3\xBF\xC9\xC4\xDC\xD5\xFD\xD4\xDA\xB1\xBB\xBD\xF8\xD0\xD0\xC9\xFD\xBC\xB6\xA1\xA3';

if(iis_head >< res && iis_body >< res)
 report_def(port:port, srv: "IIS");

#
# IIS 4.0 (NT Server Option Pack)
#
ntoptionpack_head = "welcome to iis 4.0";
ntoptionpack_body = "microsoft windows nt 4.0 option pack";

if(ntoptionpack_head >< res && ntoptionpack_body >< res)
 report_def(port:port, srv: "IIS");

#
# Domino 6.0
#

domino_head = 'body text="#000000" bgcolor="#000000" style="background-image:url(/homepage.nsf/homepage.gif?openimageresource); background-repeat: no-repeat; ">';
domino_body = "/help/help6_client.nsf";

if(domino_head >< res && domino_body >< res) report_def(port: port, srv: "Domino");

#
# iPlanet 6.0
#

iplanet_head = "<title>iplanet web server, enterprise edition 6.0</title>";
iplanet_body = '<frame name="banner" src="banner.html" scrolling="no">';


if(iplanet_head >< res && iplanet_body >< res)  report_def(port: port, srv: "iPlanet");


#
# Sambar
#

sambar_head = "<title>sambar server</title>";
sambar_body = "<b>pro server features<b>";
if(sambar_head >< res) report_def(port: port, srv: "Sambar");


#
# NetWare 6.0
#

netware_head = "<title>welcome to netware 6</title>";
netware_body = '<frame name="branding" marginwidth="7" marginheight="0" src="brand.html" noresize scrolling="no">';
if (netware_head >< res && netware_body >< res ) report_def(port: port, srv: "NetWare");


#
# BEA WebLogic Server 7.0 (thanks to Simon Ward <simon@westpoint.ltd.uk>)
#
beaweblogic_head = "<title>read me - welcome to bea weblogic server</title>";
beaweblogic_body = "welcome to bea weblogic server";
if(beaweblogic_head >< res && beaweblogic_body >< res) report_def(port: port, srv: "WebLogic");

#
# XAMPP
#
xampp_head = '<meta http-equiv="refresh" content="0;url=/xampp/">';
xampp_body = '<body bgcolor=#ffffff>\n</body>';
if(xampp_head >< res && xampp_body >< res) report_def(port: port, srv: "XAMPP");


#
# Mac OS X 10.7 Lion Server
#
lion_head = '<title>Mac OS X Lion Server</title>';
lion_body = 'you can also replace this placeholder page by adding your own index file to the folder at /Library/Server/Web/Data/Sites/Default';

if ( lion_head >< res && lion_body >< res ) report_def(port:port, srv:"Mac OS X Lion Server");

exit(0, "The web server on port "+port+" does not appear to use a default welcome page.");
