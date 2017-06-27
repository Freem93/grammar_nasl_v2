#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20250);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2005-3949", "CVE-2005-3961", "CVE-2005-3982", "CVE-2005-3982");
  script_bugtraq_id(15606, 15608, 15662, 15673);
  script_osvdb_id(21216, 21217, 21218, 21219, 21220, 21383);

  script_name(english:"WebCalendar < 1.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in WebCalendar < 1.0.2");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote version of WebCalendar does not validate input to the 'id'
and 'format' parameters of the 'export_handler.php' script before
using it to overwrite files on the remote host, subject to the
privileges of the web server user id. 

In addition, the 'activity_log.php', 'admin_handler.php',
'edit_report_handler.php', 'edit_template.php' and
'export_handler.php' scripts are prone to SQL injection attacks and
the 'layers_toggle.php' script is prone to HTTP response splitting
attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.ush.it/2005/11/28/webcalendar-multiple-vulnerabilities/" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/418286/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"https://sourceforge.net/tracker/index.php?func=detail&aid=1369439&group_id=3870&atid=303870" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WebCalendar 1.0.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/12/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/11/28");
 script_cvs_date("$Date: 2015/11/18 21:03:58 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("webcalendar_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
#
# nb: this requires the application be configured to allow public access.
install = get_kb_item(string("www/", port, "/webcalendar"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Make sure one of the affected scripts exists.
  w = http_send_recv3(method:"GET",item:string(dir, "/export_handler.php"), port:port);
  if (isnull(w)) exit(0);
  res = w[2];

  # If it does...
  #
  # nb: this appears in the case of an export error.
  if ('<span style="font-weight:bold;"' >< res) {
    # Pass a non-integer value for year; in a patched / fixed version
    # we'll get an error; otherwise, we'll get a calendar export.
    postdata = string(
      "format=ical&",
      "fromyear=nessus"
    );
    w = http_send_recv3(method:"POST", port: port,
      item: dir+"/export_handler.php?plugin="+SCRIPT_NAME,
      content_type: "application/x-www-form-urlencoded",
      data: postdata);
    if (isnull(w)) exit(0);
    res = strcat(w[0], w[1], '\r\n', w[2]);

    # There's a problem if we're able to export the calendar.
    if ("Content-Type: text/calendar" >< res) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    }
  }
}
