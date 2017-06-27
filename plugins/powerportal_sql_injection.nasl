#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15760);
 script_version("$Revision: 1.13 $");
 script_bugtraq_id(11681);
 script_osvdb_id(11876);
 
 script_name(english:"PowerPortal index.php index_page Parameter SQL Injection");

 script_set_attribute(attribute:"synopsis", value:
"It may be possible to execute arbitrary commands on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote host is using PowerPortal, a content management system, 
written in PHP. 

A vulnerability exists in the remote version of this product that 
could allow a remote attacker to perform a SQL injection attack 
against the remote host.

An attacker could exploit this flaw to execute arbitrary SQL statements 
against the remote database and possibly to execute arbitrary commands 
on the remote host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/14");
 script_cvs_date("$Date: 2011/12/15 00:34:03 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks the version of the remote PowerPortal Installation");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("powerportal_privmsg_html_injection.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
kb = get_kb_item("www/" + port + "/powerportal");
if ( ! kb ) exit(0);
matches = eregmatch(string:kb, pattern:"^(.+) under (/.*)$");
if ( ereg(pattern:"^(0\..*|1\.[0-3]([^0-9]|$))", string:matches[1]) )
{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}
