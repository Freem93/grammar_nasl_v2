#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14843);
 script_version ("$Revision: 1.22 $");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");

 script_cve_id("CVE-2004-1561");
 script_bugtraq_id(11271);
 script_osvdb_id(10406);
 script_xref(name:"Secunia", value:"12666");
 
 script_name(english:"Icecast HTTP Header Processing Remote Overflow");
 script_summary(english:"Checks Icecast version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The remote web server runs Icecast version 2.0.1 or older.  Such
versions are affected by an HTTP header buffer overflow vulnerability
that may allow an attacker to execute arbitrary code on the remote
host with the privileges of the Icecast server process. 

To exploit this flaw, an attacker needs to send 32 HTTP headers to the
remote host to overwrite a return address on the stack." );
 script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/iceexec-adv.txt" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Sep/396" );
 script_set_attribute(attribute:"see_also", value:"http://lists.xiph.org/pipermail/icecast/2004-September/007614.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Icecast 2.0.2 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Icecast Header Overwrite');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/28");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_MIXED_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
		
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8000);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8000);

banner = get_http_banner(port:port);
if (report_paranoia < 2)
{
  if (!banner || "server: icecast/" >!< tolower(banner)) exit(0);
}

if ( safe_checks() )
{
  if ( ! banner ) exit(0);
  if(egrep(pattern:"^Server: icecast/2\.0\.[0-1][^0-9]", string:banner, icase:TRUE))
      security_hole(port);
}
else
{
  if (http_is_dead(port:port)) exit(1, "The web server on port "+port+" is dead");
  h = make_array();
  for (i = 0; i < 31; i ++) h["Header"+i] = "fooBar";
  w = http_send_recv3(method: "GET", item:"/", port: port, add_headers: h);
  if (http_is_dead(port:port)) security_hole(port);
}
