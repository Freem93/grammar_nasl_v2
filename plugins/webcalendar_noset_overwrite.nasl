#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24780);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2007-1343");
  script_bugtraq_id(22834);
  script_osvdb_id(33867);

  script_name(english:"WebCalendar includes/functions.php noSet Variable Overwrite");
  script_summary(english:"Tries to overwrite variable in noSet array");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
variable overwriting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of WebCalendar installed on the remote host allows an
attacker to overwrite the 'noSet' array used by the application to
protect selected global variables.  By leveraging this issue, an
unauthenticated, remote attacker can gain control of protected global
variables, which could lead to other attacks, such as remote file
includes. 

Note that successful exploitation of this issue does not require any
special PHP settings." );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=491130" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WebCalendar 1.0.5 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/03/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/03/04");
 script_cvs_date("$Date: 2011/12/16 22:59:43 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

  script_dependencies("webcalendar_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/webcalendar");
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
if (!isnull(matches))
{
  dir = matches[2];

  # Try to generate an error by overwriting 'db_type'.
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/week.php?",
      "noSet[]=1&",
      "db_type=", SCRIPT_NAME
    ), 
    port:port
  );
  if (isnull(w)) exit(0);
  res = w[2];

  # There's a problem if we could.
  if (string("dbi_connect(): invalid db_type '", SCRIPT_NAME, "'") >< res)
  {
    security_hole(port);
    exit(0);
  }
}
