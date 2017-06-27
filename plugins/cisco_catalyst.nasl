#
# (C) Tenable Network Security, Inc.
#

#
# UNTESTED!
#


include("compat.inc");


if(description)
{
 script_id(10545);
 script_version ("$Revision: 1.36 $");
 script_cve_id("CVE-2000-0945");
 script_bugtraq_id(1846);
 script_osvdb_id(444);

 script_name(english:"Cisco Catalyst Web Interface Remote Command Execution");
 script_summary(english:"Obtains the remote router configuration");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote router has a command execution vulnerability."
 );
 script_set_attribute(attribute:"description", value:
"The remote device appears to be a Cisco Catalyst.  It is
possible to execute arbitrary commands on the router by requesting
them via HTTP, as in :

  /exec/show/config/cr

This command shows the configuration file, which contains passwords.
A remote attacker could use this flaw to take control of the router." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2000/Oct/393"
 );
 # https://web.archive.org/web/20001110134500/http://www.cisco.com/warp/public/cc/pd/si/casi/ca3500xl/index.shtml
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?3b59f033"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Disable the web configuration interface."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"plugin_publication_date", value: "2000/11/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/10/26");
 script_cvs_date("$Date: 2017/05/10 19:18:33 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/h:cisco:catalyst_3500_xl");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2017 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 1);
if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if ( "cisco-IOS" >!< banner ) exit(0);

 soc = http_open_socket(port);
 if(soc)
 {
  r = http_send_recv3(method:"GET", item:"/exec/show/config/cr", port:port);

  if(("enable" >< r) &&
     ("interface" >< r) &&
     ("ip address" >< r))security_hole(port);
  }
}
