#
# (C) Tenable Network Security, Inc.
#

# Ref:
# Message-ID: <004201c2dc64$34aa6de0$24029dd9@tuborg>
# From: Knud Erik Hojgaard <kain@ircop.dk>
# To: <bugtraq@securityfocus.com>
# Subject: clarkconnect(d) information disclosure

include("compat.inc");


if(description)
{
 script_id(11277);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2003-1379");
 script_bugtraq_id(6934);
 script_osvdb_id(50618);
 script_xref(name:"Secunia", value:"8171");
 
 script_name(english:"ClarkConnect Linux clarkconnectd Remote Information Disclosure");
 script_summary(english:"clarkconnectd detection");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"A service on the remote host is disclosing information."
 );
 script_set_attribute(attribute:"description", value:
"The 'clarkconnectd' service appears to be listening on this port.
This service provides sensitive information to remote, unauthenticated
users, such as a list of running processes, the contents of
/var/log/messages, the contents of the snort log, and more.

A remote attacker could use this information to mount further attacks." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2003/Feb/320"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Disable the clarkconnectd service."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(200);
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/02/28");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl");
 script_require_ports(10005);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");

port = 10005;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

send(socket:soc, data:string("P\r\n\r\n\r\n\r\n\r\n\r\n\r\n\r\n"));
r = recv(socket:soc, length:1024);
close(soc);
if(egrep(string:r, pattern:"root.*init")){
	register_service(port:port, proto:"clarkconnectd");
	security_warning(port);
	}
