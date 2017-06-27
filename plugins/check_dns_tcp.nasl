#
# (C) Tenable Network Security, Inc.
# 

# This is not really a security check.
# See STD0013
#
# Javier Fernandez-Sanguino mentionned 
# http://support.microsoft.com/?id=263237
# XCON: Windows 2000 and Exchange 2000 SMTP Use TCP DNS Queries


include("compat.inc");

if(description)
{
 script_id(18356);
 
 script_version ("$Revision: 1.16 $");
 script_cvs_date("$Date: 2015/10/13 15:19:32 $");

 script_name(english:"DNS Server UDP Query Limitation");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote DNS server is not RFC1035 compliant." );
 script_set_attribute(attribute:"description", value:
"A DNS server is running on this port but it only answers to UDP
requests.  This means that TCP requests are blocked by a firewall. 

This configuration is not RFC-compliant.  Contrary to common belief,
TCP transport is not restricted to zone transfers (AXFR) :

  - answers bigger than 512 bytes are always transmitted 
    over TCP.
  - for all other requests, UDP is only 'preferred' for 
    performance reasons. i.e. RFC1035 (STD0013) does not 
    forbid a DNS client from issuing its queries directly 
    over TCP." );
 script_set_attribute(attribute:"see_also", value:"http://www.faqs.org/rfcs/rfc1035.html" );
 script_set_attribute(attribute:"solution", value:
"If you are sure that the DNS server will never return answers bigger
than 512 bytes and that the client software prefers UDP (which is
nearly certain), you may ignore this message." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/22");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Checks if the remote DNS servers answers on TCP too");
 script_category(ACT_GATHER_INFO);
 script_dependencies('external_svc_ident.nasl', 'dns_server.nasl');
 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#

include('global_settings.inc');
include('misc_func.inc');

if (! thorough_tests && report_verbosity > 1)
{
 debug_print('will only run in "Verbose report" or if the "Perform thorough tests" setting is enabled.\n');
 exit(0);
}


port = get_kb_item('Services/udp/dns');
if (! port) exit(0);

if (! get_udp_port_state(port)) exit(0);	# Only on TCP?

if (verify_service(port: port, ipproto: 'tcp', proto: 'dns')) exit(0);

security_note(port: port, proto: "udp");
