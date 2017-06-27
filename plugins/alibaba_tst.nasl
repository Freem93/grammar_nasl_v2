#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10014);
 script_version ("$Revision: 1.37 $");

 script_cve_id("CVE-1999-0885");
 script_bugtraq_id(770);
 script_osvdb_id(14);

 script_name(english:"Alibaba tst.bat Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/tst.bat");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The 'tst.bat' CGI script is installed on this machine. This CGI has a
well known security flaw that would allow an attacker to read
arbitrary files on the remote system." );
 script_set_attribute(attribute:"solution", value:
"Remove the 'tst.bat' script from your web server's CGI directory
(typically cgi-bin/)." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/11/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/11/03");
 script_cvs_date("$Date: 2011/03/14 21:48:01 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 1999-2011 Tenable Network Security, Inc.");
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

function check(req, exp)
{
  local_var b, r;
  r = http_send_recv3(method:"GET", item:req, port:port);
  if (isnull(r)) exit(0);
  b = strcat(r[0], r[1], '\r\n', r[2]);
  if(exp >< b)return(1);
  return(0); 
}

foreach dir (cgi_dirs())
{
 item1 = string(dir, "/tst.bat|type%20c:\\windows\\win.ini");
 item2 = string(dir, "/tst.bat|type%20c:\\winnt\\win.ini");
 if(check(req:item1, exp:"[windows]"))
 {
  security_warning(port);
  exit(0);
 }
 if(check(req:item2, exp:"[fonts]"))
 {
  security_warning(port);
  exit(0);
 }
}
