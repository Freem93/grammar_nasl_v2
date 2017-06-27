#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CVE
#

include("compat.inc");

if(description)
{
 script_id(10554);
 script_version ("$Revision: 1.29 $");
 script_cve_id("CVE-2000-1181");
 script_bugtraq_id(1957);
 script_osvdb_id(453);
 
 script_name(english: "RealServer /admin/includes/ Remote Memory Content Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote Real Server discloses the content of its memory when issued 
the request :

	GET /admin/includes/
	
This information may be used by an attacker to obtain administrative 
control on this server, or to gain more knowledge about it." );
 script_set_attribute(attribute:"solution", value:
"Install RealServer G2 7.0update2" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"see_also", value:"http://service.real.com/help/faq/security/memory.html" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/11/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/11/16");
 script_cvs_date("$Date: 2016/12/09 20:54:57 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:realnetworks:realserver");
script_end_attributes();

 script_summary(english:"dumps the memory of a real g2 server");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_require_ports(7070, "Services/realserver");
 script_dependencies("http_version.nasl");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}


include('global_settings.inc');
include("misc_func.inc");
include("http.inc");

if ( ! thorough_tests )exit(0, "thorough_tests is not set");

port7070 = get_kb_item("Services/realserver");
if(!port7070)port7070 = 7070;

if (! get_port_state(port7070)) exit(0, "Port "+port7070+" is not open");
if ( ! get_http_banner(port:port7070) ) exit(1, "No HTTP banner on port "+port7070);

w = http_send_recv3(method:"GET", item:"/admin/includes", port:port7070);
if (" 404 " >< w[0])
{
  w = http_send_recv3(method:"GET", item:"/admin/includes/", port:port7070);
  if (isnull(w)) exit(1, "The web server on port "+port7070+" did not answer");
  headers = w[1];
  body = w[2];
    if("application/octet-stream" >!< headers) exit(0);
    if(strlen(body) > 2)
      security_warning(port7070);
}
