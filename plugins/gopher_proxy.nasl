#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(16194);
 script_version ("$Revision: 1.7 $");
 script_bugtraq_id(6782);
 script_osvdb_id(55534);

 script_name(english:"UMN Gopherd Unauthorized FTP Proxy");
 script_summary(english:"Determines if gopherd can be used as a proxy");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a Gopher server that is configured as a
proxy." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a UMN Gopher server.

It is possible to make the remote server connect to third
party FTP sites by sending the request 
'ftp://hostname.of.the.ftp.server'.

An attacker may exploit this flaw to connect to use the remote
gopher daemon as a proxy to connect to FTP servers without disclosing
their IP address.

An attacker could also exploit this flaw to 'ping' the hosts
of your network." );
 script_set_attribute(attribute:"solution", value:
"Disable FTP support in the remote gopher server" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/18");
 script_cvs_date("$Date: 2011/03/11 21:52:33 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"Firewalls"); 
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/gopher",70);
 exit(0);
}


port = get_kb_item("Services/gopher");
if ( ! port ) port = 70;
if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

send(socket:soc, data:'ftp://ftp.nessus.org\r\n');
line = recv(socket:soc, length:4096, timeout:30);

if ( "You are user #" >< line ) security_warning(port);
