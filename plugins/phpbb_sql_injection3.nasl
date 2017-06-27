#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(13655);
 script_version("$Revision: 1.16 $");

 script_bugtraq_id(10722);
 script_osvdb_id(7811, 7814);

 script_name(english:"phpBB < 2.0.9 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to SQL injection." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of phpBB older than 2.0.9.

There is a flaw in the remote software that may allow anyone
to inject arbitrary SQL commands, which may in turn be used to
gain administrative access on the remote host or to obtain
the MD5 hash of the password of any user.

One vulnerability is reported to exist in 'admin_board.php'. 
The other pertains to improper characters in the session id variable." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to 2.0.9" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/13");
 script_cvs_date("$Date: 2016/05/16 14:22:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpbb_group:phpbb");
script_end_attributes();

 
 script_summary(english:"SQL Injection");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 
 script_family(english:"CGI abuses");
 script_dependencie("phpbb_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/phpBB");
 exit(0);
}

# Check starts here

include("http_func.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

kb = get_kb_item("www/" + port + "/phpBB");
if ( ! kb ) exit(0);
matches = eregmatch(pattern:"(.*) under (.*)", string:kb);
version = matches[1];
if ( ereg(pattern:"^([01]\.|2\.0\.[0-8]([^0-9]|$))", string:version) )
{
	security_hole(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
