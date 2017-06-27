#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18368);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2014/07/14 21:05:21 $");

 script_cve_id("CVE-2005-1252");
 script_bugtraq_id(13727);
 script_osvdb_id(16805);

 script_name(english:"Ipswitch IMail Web Calendaring Server GET Request Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a directory traversal attack.");
 script_set_attribute(attribute:"description", value:
"The remote server is running Ipswitch IMail Web calendaring. 

The remote version of this software is vulnerable to a directory
traversal attack.  An attacker, exploiting this vulnerability, may be
able to retrieve sensitive files present on the server.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2721ee84");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/400545");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d4dce96");
 script_set_attribute(attribute:"solution", value:
"Apply IMail Server 8.2 Hotfix 2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/24");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:imail");
 script_end_attributes();
 
 script_summary(english:"Ipswitch IMail WebCalendar Directory Traversal Vulnerability");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8484);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8484);

banner = get_http_banner (port:port);

if ("Ipswitch Web Calendaring" >!< banner)
  exit (0);

r[0] = "nessus.jsp?\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini";
r[1] = "nessus.jsp?\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\winnt\\win.ini";

for (i=0; i < 2; i++)
{
  if (check_win_dir_trav(port: port, url: r[i]))
  {
    security_warning(port);
    exit(0);
  }
}
