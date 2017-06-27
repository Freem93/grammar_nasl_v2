#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14824);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2004-1699");
  script_bugtraq_id(11232);
  script_osvdb_id(10227);

  script_name(english:"Pinnacle ShowCenter Skin DoS");
 
  script_set_attribute(attribute:"synopsis", value:
"A remote application is vulnerable to a denial of service." );
  script_set_attribute(attribute:"description", value:
"The remote host runs the Pinnacle ShowCenter web-based interface.

The remote version of this software is vulnerable to a remote denial of 
service due to a lack of sanity checks on skin parameter.

With a specially crafted URL, an attacker can deny service of the ShowCenter 
web-based interface." );
  script_set_attribute(attribute:"solution", value:
"Upgrade to the newest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/21");
 script_cvs_date("$Date: 2011/11/28 21:39:46 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_summary(english:"Checks skin DoS in Pinnacle ShowCenter");
  script_category(ACT_DENIAL);
  
  script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 8000);
  script_dependencies("http_version.nasl");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8000);
if ( ! port ) exit(0);

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  buf = http_get(item:"/ShowCenter/SettingsBase.php?Skin=ATKnessus", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  #try to detect errors
  if(egrep(pattern:"Fatal error.*loaduserprofile.*Failed opening required", string:r))
  {
    security_warning(port);
  }
  http_close_socket(soc); 
 }
}
exit(0);
