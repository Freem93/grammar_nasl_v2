#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15618);
 script_version("$Revision: 1.20 $");

 script_cve_id("CVE-2004-2171");
 script_bugtraq_id(9496);
 script_xref(name:"OSVDB", value:3707);

 script_name(english:"Cherokee Web Server Error Page XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a cross-site scripting issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Cherokee - a fast and tiny web server.

The remote version of this software is vulnerable to cross-site
scripting attacks due to lack of sanitization in returned error pages." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76d15ca6" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Cherokee 0.4.8 or newer." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/03");
 script_cvs_date("$Date: 2016/05/04 18:02:12 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for the version of Cherokee");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Cherokee/0\.([0-3]\.|4\.[0-7])[^0-9]", string:serv))
 {
   req = http_get(item:"/<script>foo</script>", port:port);
   res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
   if ( "<script>foo</script>" >!< res ) exit(0);

   if ( func_has_arg("security_note", "confidence") )
   	security_warning(port:port, confidence:100);
   else
   	security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
 }
