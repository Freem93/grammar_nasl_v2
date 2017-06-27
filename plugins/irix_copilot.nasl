#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11369);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2000-0283", "CVE-2000-1193");
 script_bugtraq_id(1106, 4642);
 script_osvdb_id(1283, 2069);
 
 script_name(english:"Irix Performance Copilot Service Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The service 'IRIX performance copilot' is running.

This service discloses sensitive information about the remote host,
and may be used by an attacker to perform a local denial of service.

*** This warning may be a false positive since the presence
*** of the bug was not verified locally." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Apr/45" );
 script_set_attribute(attribute:"solution", value:
"Restrict access through the pmcd.conf file." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/04/12");
 script_cvs_date("$Date: 2016/11/23 20:31:32 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks the presence of IRIX copilot");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Misc."); 

 script_require_ports(4321);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");

port = 4321;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 r = recv(socket:soc, length:20);
 m = raw_string(0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00);
 if(m >< r) {
 	register_service(port:port, proto:"copilot");
 	security_warning(port);
	}
}
