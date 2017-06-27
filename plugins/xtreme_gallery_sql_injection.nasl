#
# (C) Tenable Network Security, Inc.
#

# Ref: 
#Date: 15 Jan 2004 22:58:05 -0000
#From: <posidron@tripbit.org>
#To: bugtraq@securityfocus.com
#Subject: Xtreme ASP Photo Gallery

include("compat.inc");

if(description)
{
 script_id(12020);
 script_version("$Revision: 1.23 $");
 script_cve_id("CVE-2004-2746");
 script_bugtraq_id(9438);
 script_osvdb_id(3585);

 script_name(english:"XTreme ASP Photo Gallery adminlogin.asp Multiple Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that is affected by a SQL
injection flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running XTreme ASP Photo Gallery. 

There is a flaw in the version of this software installed on the
remote host that may allow anyone to inject arbitrary SQL commands,
which may in turn be used to gain administrative access on the remote
host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/350028" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/01/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/01/15");
 script_cvs_date("$Date: 2011/03/12 01:05:18 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 
 script_summary(english:"SQL Injection in XTreme ASP Photo Gallery");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/ASP");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


global_var	port;

function check(req)
{
  local_var r, buf, host, variables;

  # Make sure script exists.
  r = http_send_recv3(method:"GET",item:req, port:port);
  if (isnull(r)) exit(0);

  if ("<title>Login - XTREME ASP Photo Gallery</title>" >< r[2]) {
   host = get_host_name();
   variables = string("username='&password=y&Submit=Submit");
   r = http_send_recv3(method: "POST", item: req, port: port,
     exit_on_fail: 1,
     content_type: "application/x-www-form-urlencoded", data: variables);
   buf = r[2];
   if("in query expression 'username=''' AND password='y'" >< buf && "80040e14" >< buf)
   	{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
	}
 }
}

port = get_http_port(default:80, asp: 1);


if (thorough_tests) dirs = list_uniq(make_list("/photoalbum", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  check(req:dir + "/admin/adminlogin.asp");
 }
