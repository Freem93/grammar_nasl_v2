#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39446);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/09 20:31:00 $");

  script_name(english:"Apache Tomcat Default Error Page Version Detection");
  script_summary(english:"Attempts to get a Tomcat version number from a 404 page.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server reports its version number on error pages.");
  script_set_attribute(attribute:"description", value:
"Apache Tomcat is running on the remote host and is reporting its
version number on the default error pages. A remote attacker can
exploit this information to mount further attacks.");
  script_set_attribute(attribute:"see_also", value:"http://wiki.apache.org/tomcat/FAQ/Miscellaneous#Q6");
  script_set_attribute(attribute:"see_also", value:"http://jcp.org/en/jsr/detail?id=315");
  script_set_attribute(attribute:"solution", value:
"Replace the default error pages with custom error pages to hide the
version number. Refer to the Apache wiki or the Java Servlet
Specification for more information.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("backport.inc");

port   = get_http_port(default:8080);
banner = get_http_banner(port:port);

if (!banner) audit(AUDIT_WEB_BANNER_NOT, port);
if (
  "Server: Apache Coyote" >< banner ||    # 4.1.18-LE-jdk14
  "Server: Apache-Coyote" >< banner ||
  "Server: Apache Tomcat" >< banner ||
  "Server: Tomcat Web Server" >< banner ||
  "Servlet-Engine: Tomcat Web Server" >< banner
)
{
  set_kb_item(name:"www/tomcat", value:TRUE);
  set_kb_item(name:"www/"+port+"/tomcat", value:TRUE);
}
else
{
  if (report_paranoia < 2)
    audit(AUDIT_WRONG_WEB_SERVER, port, "Apache Tomcat");
}

# Request a page that will likely return a 404, and see if it includes
# a version number
url = string("/nessus-check/", SCRIPT_NAME);
res = http_send_recv3(method:"GET", item:url, port:port, fetch404:TRUE, exit_on_fail:TRUE);

if (res[0] =~ '^HTTP/1\\.[01] +404 ')
{
  backport_404 = get_backport_banner(banner: res[1] + '\r\n' + res[2]);
  if (!backported)
  {
    # Identify ManageEngine products.
    res2 = http_send_recv3(method:"GET", item:"/event/index2.do", port:port, follow_redirect:1, exit_on_fail:TRUE);
    if (
      res2[2] &&
      (
        "<title>ManageEngine" >< res2[2] &&
        ">ZOHO Corp.</a>" >< res2[2] &&
        'support@manageengine.com">' >< res2[2]
      )
    ) backported = TRUE;
  }

  # Obtain and save the possibly-backported version
  pattern = '((Server:|Servlet-Engine:) Tomcat Web Server|<title>Apache Tomcat)/([0-9\\.]+([^0-9][0-9]+|-[^0-9]+[0-9]+)?)';
  match = eregmatch(string:backport_404, pattern:pattern, icase:TRUE);
  if (isnull(match))
    audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "Apache Tomcat", port);

  version = match[3];
  source  = match[0];
  set_kb_item(name:"tomcat/" + port + "/error_version", value:version);
  set_kb_item(name:"tomcat/" + port + "/version_source", value:source);

  # If backported, preserve and store the detected original version
  if (backported)
  {
    match = eregmatch(string:res[1]+res[2], pattern:pattern, icase:TRUE);
    if (isnull(match))
      audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "Apache Tomcat", port);

    orig_version = match[3];
    orig_source  = match[0];
    set_kb_item(name:"tomcat/" + port + "/orig_error_version", value:orig_version);
    set_kb_item(name:"tomcat/" + port + "/orig_version_source", value:orig_source);
  }

  # In case the banner was modified.
  replace_kb_item(name:"www/tomcat", value:TRUE);
  replace_kb_item(name:"www/"+port+"/tomcat", value:TRUE);

  if ( report_paranoia < 2 && backported )
  {
    set_kb_item(name:"tomcat/"+port+"/backported", value:TRUE);
    report_backported_note = '\n' +
      '\n  Note    : This installation may have backported patches; therefore,' +
      '\n            version checks will not be run in non-paranoid scan modes.';

    # Use originally detected version in report for
    # non-paranoid scans
    source = orig_source;
    version = orig_version;
  }

  if (report_verbosity > 0)
  {
    report = '\n' +
      'Nessus found the following version information on an Apache Tomcat\n' +
      '404 page or in the HTTP Server header :' +
      '\n' +
      '\n  Source  : ' + source +
      '\n  Version : ' + version;
    if (!isnull(report_backported_note))
      report = report + report_backported_note;
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
