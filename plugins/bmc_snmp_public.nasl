#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(51160);
 script_version ("$Revision: 1.3 $");
 script_cvs_date("$Date: 2016/11/11 20:08:42 $");


 script_name(english:"BMC SNMP Agent Default Community Name (public)");
 script_summary(english:"Default community names of the SNMP Agent");

 script_set_attribute(
  attribute:"synopsis",
  value:"The community name of the remote SNMP server is set to 'public'."
 );
 script_set_attribute(
  attribute:"description",
  value:
"The remote SNMP server, listening on port 8161 (probably part of BMC
Patrol) has a community name set to 'public'. 

An attacker may use this information to gain more knowledge about the
remote host or to change the configuration of the remote system (if
the default community allow such modifications)."
 );
 script_set_attribute(
  attribute:"solution",
  value:
"Configure BMC patrol to disable SNMP or change the community to
something hard to guess."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");


 script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/14");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
 script_family(english:"SNMP");
 script_dependencies("find_service2.nasl");
 exit(0);
}

include ("global_settings.inc");
include ("misc_func.inc");
include ("snmp_func.inc");

set_snmp_version( version:0 );


port = 8161;
if (!get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc) exit(1, "Can't open socket on UDP port "+port+".");

rep = snmp_request_next(socket:soc, community:"public", oid:"1.3");
close(soc);
if ( ! isnull(rep) && !isnull(rep[1]) ) security_hole(port:port, proto:"udp", extra:'\nRequesting the OID 1.3 returned :\n' +
	'\n  OID   : ' + rep[0] + '\n' +
	'\n  Value : ' + rep[1] + '\n');

