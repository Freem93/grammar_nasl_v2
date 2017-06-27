#
# (C) Tenable Network Security, Inc.
#

# See the Nessus Scripts License for details
#

include("compat.inc");

if(description)
{
 script_id(11690);
 script_bugtraq_id(7764);
 script_osvdb_id(4652);
 script_version("$Revision: 1.15 $");
 
 script_name(english:"JBoss %00 Request JSP Source Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to information disclosure attacks." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote web server disclose the source code of
its JSP pages by appending a NULL character to the name of the JSP files
requested (eg, 'foo.jsp%00').  An attacker may use this flaw to get the
source code of scripts on the remote host and possibly obtain passwords
and other sensitive information." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/323430" );
 script_set_attribute(attribute:"solution", value:
"None at this time" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/30");
 script_cvs_date("$Date: 2011/03/14 21:48:06 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Attempts to read the source of a jsp page");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

global_var	port;

function check(file)
{
 local_var	w, res;

 w = http_send_recv3(method:"GET", item:file, port:port, exit_on_fail: 1);
 res = strcat(w[0], w[1], '\r\n', w[2]);
 if("<%" >< res) return 1;
 return 0;
}

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8080);
foreach port (ports)
{
 if(get_port_state(port))
 {
 files = get_kb_list(string("www/", port, "/content/extensions/jsp"));
 if(isnull(files))files = make_list("/web-console/ServerInfo.jsp");
 n = 0;
 foreach file (files)
  {
  if(check(file:file) == 0)
   {
   file = str_replace(string:file, find:".jsp", replace:".jsp%00");
   if(check(file:file)) { security_warning(port); exit(0); }
  }
  n ++;
  if(n > 20)break;
  }
 }
}
