#
# This script was written by deepquest <deepquest@code511.com>
# 
# See the Nessus Scripts License for details
#
# Modifications by rd:
# -  added ref: http://www.cert.org/advisories/CA-2002-32.html
# -  removed leftovers in the code (send(raw_string(0, 0))
# -  added the use of telnet_init()
# -  replaced open_sock_udp by open_sock_tcp()
# -  added script id
# -  attributed copyright properly to deepquest
# -  merged some ideas from Georges Dagousset <georges.dagousset@alert4web.com> 
#    who wrote a duplicate of this script
#
#----------
# XXXX Untested!
#
# @DEPRECATED@
#
# Disabled on 2015/07/07 due to excessive false positives since it flags any telnet banner discovered on TCP 6778.


include("compat.inc");

if (description)
{
 script_id(11170);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2015/07/07 20:56:41 $");

 script_cve_id("CVE-2002-1272");
 script_bugtraq_id(6220);
 script_osvdb_id(15411);
 script_xref(name:"CERT-CC", value:"CA-2002-32");

 script_name(english:"Alcatel OmniSwitch 7700/7800 Switches Backdoor Access (deprecated)");
 script_summary(english:"Checks for the presence of backdoor in Alcatel 7700/7800 switches.");

 script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated." );
 script_set_attribute(attribute:"description", value:
"This plugin has been deprecated due to excessive false positives since
it flags any telnet banner discovered on TCP 6778.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/11/22");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/11/26");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002-2015 deepquest");
 script_family(english:"Backdoors");
 script_dependencie("find_service1.nasl");
 script_require_ports(6778);
 exit(0);
}

exit(0, 'This plugin is disabled indefinitely since it is prone to false positives.');

include("global_settings.inc");
include("telnet_func.inc");
include("misc_func.inc");

port = 6778;
if (! get_port_state(port)) exit(0, "Port "+port+" is closed.");
p = known_service(port:port);
if(p && p != "telnet" && p != "aos")exit(0);


soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot open connection to TCP port "+port+".");

  data = get_telnet_banner(port:port);
 if(data)
  {
  security_hole(port:port,extra:
'The banner:\n' + data + 
'\nshould be reported to <svc-signatures@nessus.org>\n' );
  register_service(port: port, proto: "aos");
  }

