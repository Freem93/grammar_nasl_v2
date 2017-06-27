#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11487);
 script_version ("$Revision: 1.18 $");

 script_cve_id("CVE-2003-1181");
 script_bugtraq_id(7171);
 script_osvdb_id(3292);
 
 script_name(english:"Advanced Poll info.php Remote Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Chien Kien Uong's Advanced Poll, a simple
Poll system using PHP. 

By default, this utility includes a file named 'info.php' that makes a
call to 'phpinfo()' and displays a lot of information about the remote
host and how PHP is configured.  An attacker may use this flaw to gain
a more intimate knowledge about the remote host and better prepare its
attacks." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/342493" );
 script_set_attribute(attribute:"solution", value:
"Delete the affected file." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/10/25");
 script_cvs_date("$Date: 2017/03/09 14:56:41 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for the presence of info.php");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_dependencies("http_version.nasl");
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
if ( !can_host_php(port:port) ) exit(0);


foreach dir (list_uniq(make_list("/poll", cgi_dirs())))
{
 r = http_send_recv3(method:"GET", item:string(dir, "/misc/info.php"), port:port);
 if (isnull(r)) exit(0);
 res = r[2];
 if("<title>phpinfo()</title>" >< res)
 	{
	security_warning(port);
	exit(0);
	}
}
