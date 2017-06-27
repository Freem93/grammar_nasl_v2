#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11620);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2003-0270");
 script_bugtraq_id(7554);
 script_osvdb_id(12073);
 script_xref(name:"Secunia", value:"8773");

 script_name(english:"Apple AirPort Base Station Authentication Credential Encryption Weakness");
 script_summary(english:"Connects to port 5009 and says 'Hello'");

 script_set_attribute(attribute:"synopsis", value:
"The remote wireless access point contains a password encryption
weakness." );
 script_set_attribute(attribute:"description", value:
"The remote host is an Apple Airport Wireless Access Point which
can be administrated on top of TCP port 5009.

There is a design flaw in the administrative protocol which makes
the clients which connect to this port send the password
in cleartext (although slightly obsfuscated).

An attacker who has the ability to sniff the data going to this
device may use this flaw to gain its administrative password and
gain its control. Since the airport base station does not keep any
log, it will be difficult to determine that administrative access
has been stolen." );
 script_set_attribute(attribute:"solution", value:
"Block incoming traffic to this port, and only administer
this base station when connected to it using a cross-over ethernet
cable." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/12");
 script_cvs_date("$Date: 2015/06/23 19:16:51 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencies("find_service1.nasl");
 script_require_ports(5009);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");

port = 5009;
if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(!soc)exit(0);
req = "acpp" + crap(data:raw_string(0), length:124);
send(socket:soc, data:req);
r = recv(socket:soc, length:128);
if(!r)exit(0);
if("acpp" >< r && r != req){
	security_hole(port);
	register_service(port:5009, proto:"apple-airport-admin");
	}
