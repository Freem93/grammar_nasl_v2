#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) 
{
  script_id(21307);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-2059", "CVE-2006-2060", "CVE-2006-2061");
  script_bugtraq_id(17690, 17695);
  script_osvdb_id(25005, 25006, 25008);

  script_name(english:"Invision Power Board 2.x.x < 04-25-06 Multiple Vulnerabilities");
  script_summary(english:"Checks for ck parameter SQL injection vulnerability in IPB");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to multiple types of attacks." );
 script_set_attribute(attribute:"description", value:
"The installation of Invision Power Board on the remote host fails to
sanitize input to the 'ck' parameter of the 'index.php' script before
using it in database queries.  An unauthenticated attacker may be able
to leverage this issue to disclose sensitive information, modify data,
or launch attacks against the underlying database. 

In addition, the application reportedly allows for execution of
arbitrary PHP code contained in a posting due to a flaw in the
'search.php' script, remote file includes (requires admin capability),
and cross-site scripting attacks using specially crafted JPEG file." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/431990/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://forums.invisionpower.com/index.php?showtopic=213374" );
 script_set_attribute(attribute:"solution", value:
"Apply the IPB 2.x.x 04-25-06 Security Update referenced in the vendor
URL above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/04/25");
 script_cvs_date("$Date: 2016/11/23 20:31:32 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:invisionpower:invision_power_board");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("invision_power_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/invision_power_board");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(pattern:"^(.+) under (/.*)$", string:install);
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw to generate a SQL syntax error.
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/index.php?",
      "act=task&",
      "ck='", SCRIPT_NAME
    ),
    port:port
  );
  if (isnull(w)) exit(1, "The web server did not answer");
  res = w[2];

  # There's a problem if we see a syntax error.
  if (egrep(pattern:string("mySQL query error: SELECT .+task_manager +WHERE task_cronkey=''", SCRIPT_NAME), string:res))
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
