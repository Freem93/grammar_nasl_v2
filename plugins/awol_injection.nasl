#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11102);
 script_bugtraq_id(3387);
 script_osvdb_id(1959);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-2001-1048");

 script_name(english:"AWOL helperfunction.php includedir Parameter Remote File Inclusion");
 script_summary(english:"Checks for the presence of includes/awol-condensed.inc.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a PHP application that is affected by a
remote code execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running AWOL, an open source PHP application. It is
possible to make the remote host include php files hosted on a third
party server using the '$include' variable in AWOL.

An attacker may use this flaw to inject arbitrary code in the remote
host and gain a shell with the privileges of the web server." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Oct/12" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/08/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/10/02");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:topher1kenobe:awol");
script_end_attributes();

 
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);

function check(url)
{
 local_var r, w;
 w = http_send_recv3(method:"GET", item:string(url, "/includes/awol-condensed.inc.php?path=http://xxxxxxxx/"),
 		port:port);
 if (isnull(w)) exit(0);
 r = strcat(w[0], w[1], '\r\n', w[2]);
 if("http://xxxxxxxx/config.inc.php" >< r)
        {
 	security_hole(port);
	exit(0);
	}
}

check(url:"");
foreach dir (cgi_dirs())
{
check(url:dir);
}
