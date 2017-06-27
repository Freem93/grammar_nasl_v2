#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88099);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/02/02 21:28:13 $");

  script_name(english:"Web Server HTTP Header Information Disclosure");
  script_summary(english:"Checks for server and versions in HTTP headers.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server discloses information via HTTP headers.");
  script_set_attribute(attribute:"description", value:
"The HTTP headers sent by the remote web server disclose information
that can aid an attacker, such as the server version and languages
used by the web server.");
  script_set_attribute(attribute:"solution", value:
"Modify the HTTP headers of the web server to not disclose detailed
information about the underlying web server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "peercast_installed.nasl", "www_fingerprinting_hmap.nasl", "tomcat_error_version.nasl", "websphere_detect.nasl", "apache_http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Quick check for an X-Powered-By Header field
function check_xpower(banner)
{
  local_var pat, match;

  pat = "(X-Powered-By.*[^\t|\n])";

  match =  eregmatch(
    pattern : pat,
    string  : banner,
    icase   : TRUE
  );

  if (!empty_or_null(match))
    return match[1];
  else
    return NULL;
}

function vreport(type, source, version, xpower, port)
{
  local_var report;
  report = '';

  report += '\n Server type     : ' + type;
  if (!empty_or_null(version))
    report += '\n Server version  : ' + version;
  if (!empty_or_null(source))
    report += '\n Source          : ' + source;
  if (!isnull(xpower))
    report += '\n Additional data : ' + xpower;

  report += '\n';

  if (report_verbosity > 0)
    security_warning(port:port, extra:report);
  else security_warning(port);
  exit(0);
}

port = get_http_port(default:80);

vuln = FALSE;
xpower_hdr = NULL;

banner = get_http_banner(port: port, exit_on_fail:TRUE);

server = egrep(string:banner, pattern:"^Server:", icase:TRUE);
if (!server)
  audit(AUDIT_WEB_NO_SERVER_HEADER, port);

server = ereg_replace(string:chomp(server), pattern:"^Server: *", replace:"", icase:TRUE);

######################################################################
# Apache
#
# Version is extracted in apache_http_version.nasl
#
######################################################################
chk_apache = get_kb_item("www/" + port + "/apache");
if (chk_apache)
{
  server_ver = get_kb_item("www/apache/" + port + "/pristine/version");
  type = "Apache";

  if (!isnull(server_ver))
  {
    source = get_kb_item("www/apache/" + port + "/pristine/version");
    vuln = TRUE;
  }
  else
  {
    server_ver = get_kb_item("www/apache/" + port + "/version");
    if (!isnull(server_ver))
    {
      source = get_kb_item("www/apache/" + port + "/source");
      vuln = TRUE;
    }
  }
  if (!isnull(source))
  {
    xpower = check_xpower(banner:banner);
    if (xpower) xpower_hdr = xpower;
  }

  if (vuln || !isnull(xpower_hdr))
    vreport(type:type, source:source, version:server_ver, xpower:xpower_hdr, port:port);
}

######################################################################
# Apache JServ
######################################################################
if (server =~ "^(Apache|Mod_)JServ/")
{
  ver = eregmatch(
    pattern : "^((Apache|Mod_)JServ)/([0-9\.]+($|[^\s]+))",
    string  : server
  );

  if (!empty_or_null(ver))
  {
    vuln = TRUE;
    type = ver[1];
    server_ver = ver[3];
    source = server;
  }
  xpower = check_xpower(banner:banner);
  if (xpower) xpower_hdr = xpower;

  if (vuln || !isnull(xpower_hdr))
    vreport(type:type, source:source, version:server_ver, xpower:xpower_hdr, port:port);
}

######################################################################
# CERN httpd
######################################################################
if (ereg(pattern:"^(CERN httpd(\s)?|CERN/)", string:server, icase:TRUE))
{
  type = "CERN";
  ver = eregmatch(
    pattern : "^(CERN httpd(\s)?|CERN/)([0-9\.]+($|.*[^\n]))",
    string  : server,
    icase   : TRUE
  );
  if (!empty_or_null(ver))
  {
    vuln = TRUE;
    server_ver = ver[3];
    source = server;
  }
  xpower = check_xpower(banner:banner);
  if (xpower) xpower_hdr = xpower;

  if (vuln || !isnull(xpower_hdr))
    vreport(type:type, source:source, version:server_ver, xpower:xpower_hdr, port:port);

}

######################################################################
# Domino
#
# Version is extracted in domino_installed.nasl and banner that plugin uses is
# in the www/real_banner KB key
#
######################################################################
chk_domino = get_kb_item("www/domino");
if (chk_domino)
{
  server_ver = get_kb_item("www/Domino/"+port+"/version");

  if (!isnull(server_ver))
  {
    source = get_kb_item("www/real_banner/"+port);
    vuln = TRUE;
    type = "IBM Domino";

   # Unlikely to be found on a Domino Server but adding just in case
    xpower = check_xpower(banner:banner);
    if (xpower) xpower_hdr = xpower;
  }
  if (vuln || !isnull(xpower_hdr))
    vreport(type:type, source:source, version:server_ver, xpower:xpower_hdr, port:port);
}

######################################################################
# iPlanet and related servers
######################################################################
if (ereg(pattern:"^(Oracle-)?iPlanet", string:server, icase:TRUE))
{
  type = "iPlanet";
  ver = eregmatch(
    pattern : "^(Oracle-iPlanet-Web-Server|iPlanet(-|\s)WebServer(-Enterprise)?)/([0-9\.]+($|[^\s]*))",
    string  : server,
    icase   : TRUE
  );
  if (!empty_or_null(ver[4]))
  {
    vuln = TRUE;
    server_ver = ver[4];
    source = server;
  }
  xpower = check_xpower(banner:banner);
  if (xpower) xpower_hdr = xpower;

  if (vuln || !isnull(xpower_hdr))
    vreport(type:type, source:source, version:server_ver, xpower:xpower_hdr, port:port);
}

if (server =~ "^Netscape")
{
  type = "Netscape Enterprise Server";
  ver = eregmatch(
    pattern : "^Netscape-(Enterprise|Commerce|Communications|FastTrack)/([0-9\.]+($|[^\s]*))",
    string  : server
  );

  if (!empty_or_null(ver[2]))
  {
    vuln = TRUE;
    server_ver = ver[2];
    source = server;
  }
  xpower = check_xpower(banner:banner);
  if (xpower) xpower_hdr = xpower;

  if (vuln || !isnull(xpower_hdr))
    vreport(type:type, source:source, version:server_ver, xpower:xpower_hdr, port:port);
}

if (server =~ "^Sun(-)?(Java|One|ONE)")
{
  type = "Sun ONE Web Server";
  ver = eregmatch(
    pattern : "^Sun(-)?(Java(-|\s)System|One|ONE)(-|\s)?Web(-|\s)?Server(/|\s)([0-9\.]+($|[^\s]*))",
   string   : server,
   icase    : TRUE
  );

   if (!empty_or_null(ver[7]))
  {
    vuln = TRUE;
    server_ver = ver[7];
    source = server;
  }
  xpower = check_xpower(banner:banner);
  if (xpower) xpower_hdr = xpower;

  if (vuln || !isnull(xpower_hdr))
    vreport(type:type, source:source, version:server_ver, xpower:xpower_hdr, port:port);
}

######################################################################
# JBoss AS (Application Server)
######################################################################
if (banner =~ "JBoss")
{
  banner = eregmatch(pattern:"X-Powered-By: (.*)", string:banner);
  if (!empty_or_null(banner))
    banner = banner[1];

  match = NULL;
  if ("JBossAS" >< banner)
  {
    type = "JBossAS";
    match = eregmatch(
      pattern : "(Servlet(\s|\/)[0-9.]+); (((JBossAS-([0-9.]+))))",
      string  : banner
    );
  }
  else
  {
    type = "JBoss";
    match = eregmatch(
      pattern : "(Servlet(\s|\/)[0-9.]+); ((JBoss|Tomcat)?-[0-9.]+/)?(JBoss-([^\/\s\)]+))",
      string  : banner
    );
  }

  if (!empty_or_null(match[6]))
  {
    server_ver = match[6];
    vuln = TRUE;
    source = banner;

    if (!empty_or_null(match[1]))
       xpower_hdr = match[1];

    build = eregmatch(pattern:"(build:.*)", string:banner);
    if (!empty_or_null(build))
    {
      if (!isnull(xpower_hdr))
        xpower_hdr += '\n                   ' + build[1];
      else
        xpower_hdr = build[1];
    }
  }
  if (vuln || !isnull(xpower_hdr))
    vreport(type:type, source:source, version:server_ver, xpower:xpower_hdr, port:port);
}

######################################################################
# KNet Web Server
######################################################################
if (server =~ "^KNet( vv)?")
{
  type = 'KNet Web Server';
  ver = eregmatch(
    pattern : "^KNet( Web Server/| vv)([0-9\.]+($|[^\n]+))",
    string  : server,
    icase   : TRUE
  );
  if (!empty_or_null(ver))
  {
    vuln = TRUE;
    server_ver = ver[2];
    source = server;
  }
  xpower = check_xpower(banner:banner);
  if (xpower) xpower_hdr = xpower;

  if (vuln || !isnull(xpower_hdr))
    vreport(type:type, source:source, version:server_ver, xpower:xpower_hdr, port:port);
}

######################################################################
# Light HTTPD
# https://www.lighttpd.net/
######################################################################
if (server =~ "^lighttpd")
{
  type = 'lighttpd';
  ver = eregmatch(
    pattern : "^(lighttpd v |lighttpd/)([0-9\.]+($|[^\n]+))",
    string  : server,
    icase   : TRUE
  );

  if (!empty_or_null(ver))
  {
    vuln = TRUE;
    server_ver = ver[2];
    source = server;
  }
  xpower = check_xpower(banner:banner);
  if (xpower) xpower_hdr = xpower;

  if (vuln || !isnull(xpower_hdr))
    vreport(type:type, source:source, version:server_ver, xpower:xpower_hdr, port:port);
}

######################################################################
# Microsoft IIS
######################################################################
if (server =~ "^Microsoft-IIS")
{
  type = 'Microsoft IIS';
  ver = eregmatch(
    pattern : "^Microsoft-IIS/([0-9\.]+)",
    string  : server
  );

  if (!empty_or_null(ver))
  {
    vuln = TRUE;
    server_ver = ver[1];
    source = server;
  }
  xpower = check_xpower(banner:banner);
  if (xpower) xpower_hdr = xpower;

  net_ver = eregmatch(
    pattern : "(X-AspNet-Version: [^\n]+)",
    string  : banner
  );

  if (!empty_or_null(net_ver))
  {
    if (!isnull(xpower_hdr))
       xpower_hdr += '\n                   ' + net_ver[1];
    else xpower_hdr = net_ver[1];
  }

  if (vuln || !isnull(xpower_hdr))
    vreport(type:type, source:source, version:server_ver, xpower:xpower_hdr, port:port);
}

######################################################################
# NCSA HTTPd
######################################################################
if (server =~ "^NCSA(/|\s)")
{
  type = 'NCSA';
  ver = eregmatch(
    pattern : "^NCSA(/|\s)?([0-9\.]+($|[^\n]+))",
    string  : server,
    icase   : TRUE
  );

  if (!empty_or_null(ver))
  {
    vuln = TRUE;
    server_ver = ver[2];
    source = server;
  }
  xpower = check_xpower(banner:banner);
  if (xpower) xpower_hdr = xpower;

  if (vuln || !isnull(xpower_hdr))
    vreport(type:type, source:source, version:server_ver, xpower:xpower_hdr, port:port);
}

######################################################################
# NGINX
######################################################################
if (tolower(server) =~ "^nginx")
{
  type = 'NGINX';
  ver = eregmatch(
    pattern : "^nginx\/(.*)$",
    string  : server,
    icase   : TRUE
  );

  if (!empty_or_null(ver))
  {
    vuln = TRUE;
    server_ver = ver[1];
    source = server;
  }
  xpower = check_xpower(banner:banner);
  if (xpower) xpower_hdr = xpower;

  if (vuln || !isnull(xpower_hdr))
    vreport(type:type, source:source, version:server_ver, xpower:xpower_hdr, port:port);
}

######################################################################
# PeerCast
######################################################################
peercast_version = get_kb_item("PeerCast/"+port+"/version");
if (!isnull(peercast_version) && server =~ "^PeerCast")
{
  vuln = TRUE;
  type = "PeerCast";
  server_ver = peercast_version;
  source = server;

  xpower = check_xpower(banner:banner);
    if (xpower) xpower_hdr = xpower;

  if (vuln || !isnull(xpower_hdr))
    vreport(type:type, source:source, version:server_ver, xpower:xpower_hdr, port:port);
}

######################################################################
# SAMBAR
######################################################################
if (server =~ "^SAMBAR")
{
  type = 'SAMBAR';

  ver = eregmatch(
    pattern : "^SAMBAR ([0-9\.]+($|[^\n]+))",
    string  : server
  );

  if (!empty_or_null(ver))
  {
    vuln = TRUE;
    server_ver = ver[1];
    source = server;
  }
  xpower = check_xpower(banner:banner);
  if (xpower) xpower_hdr = xpower;

  if (vuln || !isnull(xpower_hdr))
    vreport(type:type, source:source, version:server_ver, xpower:xpower_hdr, port:port);
}

######################################################################
# Savant Web Server
######################################################################
if (server =~ "^Savant/")
{
  type = 'Savant Web Server';

  ver = eregmatch(
    pattern : "^Savant/([0-9\.]+($|[^\n]+))",
    string  : server
  );

  if (!empty_or_null(ver))
  {
    vuln = TRUE;
    server_ver = ver[1];
    source = server;
  }
  xpower = check_xpower(banner:banner);
  if (xpower) xpower_hdr = xpower;

  if (vuln || !isnull(xpower_hdr))
    vreport(type:type, source:source, version:server_ver, xpower:xpower_hdr, port:port);
}

######################################################################
# Oracle Application Server
######################################################################
if (server =~ "^Oracle-Application-Server")
{
  type = 'Oracle Application Server';

  ver = eregmatch(
    pattern : "^Oracle-Application-Server-([0-9\.]+($|[^\s]+))",
    string  : server
  );

  if (!empty_or_null(ver))
  {
    vuln = TRUE;
    server_ver = ver[1];
    source = server;
  }
  xpower = check_xpower(banner:banner);
  if (xpower) xpower_hdr = xpower;

  if (vuln || !isnull(xpower_hdr))
    vreport(type:type, source:source, version:server_ver, xpower:xpower_hdr, port:port);
}

######################################################################
# Apache Tomcat
#
# Version is extracted by tomcat_error_version.nasl however we will
# grab the version from the banner (if possible) since this plugin is
# for information leakage in the HTTP headers
#
######################################################################
chk_tomcat = get_kb_item("www/"+port+"/tomcat");
if (chk_tomcat)
{
  if (
    "Server: Apache Coyote" >< banner ||
    "Server: Apache-Coyote" >< banner ||
    "Server: Apache Tomcat" >< banner ||
    "Server: Tomcat Web Server" >< banner ||
    "Servlet-Engine: Tomcat Web Server" >< banner
  )
  {
    match = eregmatch(
       pattern :'((Server:|Servlet-Engine:) Tomcat Web Server|Apache Tomcat)/([0-9.]+)',
       string  : banner
    );

    if (!empty_or_null(match[3]))
    {
      server_ver = match[3];
      vuln = TRUE;
      source = match[0];
      type = "Apache Tomcat";

      xpower = check_xpower(banner:banner);
        if (xpower) xpower_hdr = xpower;

      if (vuln || !isnull(xpower_hdr))
        vreport(type:type,source:source,version:server_ver,xpower:xpower_hdr, port:port);
    }
  }
}

######################################################################
# WebSphere Application Server
#
# Version is extracted in websphere_detect.nasl
#
######################################################################
chk_WAS = get_kb_item("www/WebSphere");
if (chk_WAS)
{
  server_ver = get_kb_item("www/WebSphere/"+port+"/version");
  type = "WebSphere Application Server";

  if (!isnull(server_ver))
  {
    source = get_kb_item("www/WebSphere/"+port+"/source");
    vuln = TRUE;

    xpower = check_xpower(banner:banner);
    if (xpower) xpower_hdr = xpower;
  }
  if (vuln || !isnull(xpower_hdr))
    vreport(type:type, source:source, version:server_ver, xpower:xpower_hdr, port:port);
}

######################################################################
exit(0, "The web server on port "+port+" does not disclose sensitive information in the Server response header.");
