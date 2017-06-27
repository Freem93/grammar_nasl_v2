#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18571);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-2320");
  script_bugtraq_id(14072);
  script_osvdb_id(17581);

  script_name(english:"WebCalendar assistant_edit.php Unauthorized Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP script that allows unauthorized
access." );
 script_set_attribute(attribute:"description", value:
"The remote version of WebCalendar fails to restrict access to the
script 'assistant_edit.php'.  An attacker can use this script to
change assistants and to display all users in the system even when the
'Public access can view other users' setting has been disabled." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=328057" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WebCalendar 1.0.0 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/26");
 script_cvs_date("$Date: 2011/03/14 21:48:15 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for assistant_edit.php unauthorized access vulnerability in WebCalendar");
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");

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
install = get_kb_item(string("www/", port, "/webcalendar"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to call the script directly.
  w = http_send_recv3(method:"GET", item:string(dir, "/assistant_edit.php"), port:port);
  if (isnull(w)) exit(0);
  res = w[2];

  # There's a problem if we get the page -- the fix redirects
  # people to the month view (or whatever the startview is).
  if ('<FORM ACTION="assistant_edit_handler.php"' >< res) {
    security_hole(port);
    exit(0);
  }
}
