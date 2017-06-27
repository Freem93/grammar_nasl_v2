#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(11966);
  script_version("$Revision: 1.20 $");
  script_bugtraq_id(9309);
  script_osvdb_id(3254);

  script_name(english:"PHP-Ping php-ping.php count Parameter Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows for arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running 'php-ping.php' from
TheWorldsEnd.NET.  The remote version of this script does not properly
sanitize the 'count' parameter and allows attackers to execute
arbitrary commands or read arbitrary files on the remote host subject
to the privileges of the web server user id." );
 script_set_attribute(attribute:"solution", value:
"Remove or update the affected script." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/12/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/12/30");
 script_cvs_date("$Date: 2012/09/12 01:38:22 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:theworldsend.net:php-ping");
script_end_attributes();

  script_summary(english:"Detect PHP Ping Code Execution");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2003-2012 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);

http_check_remote_code (
			extra_check:"</body>Ping Output:<br><pre>",
			check_request:"/php-ping.php?host=test&submit=Ping!&count=1|id||",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id" );
