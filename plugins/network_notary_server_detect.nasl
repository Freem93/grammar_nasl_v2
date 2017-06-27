#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34447);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2011/05/24 20:37:08 $");

  script_name(english:"Network Notary Server Detection");
  script_summary(english:"Queries a notary for www.nessus.org");

 script_set_attribute(attribute:"synopsis", value:
"A network service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service is a Perspectives Network Notary Server. 
Perspectives is a framework to authenticate public keys for various
network services, and a Network Notary monitors and records the public
keys used by various network services." );
 script_set_attribute(attribute:"see_also", value:"http://www.cs.cmu.edu/~perspectives/index.html" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/21");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  exit(0);
}

include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");


port = 15217;
if (known_service(port:port, ipproto:"udp")) exit(0);
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc) exit(0);


# Query a service.
#
# nb: format is "<dns-name>:<port>,<service-type>", and
#     service-type 2 is for SSL servers.
service = "www.nessus.org:443,2";
TYPE_FETCH_REQ           = 1;
TYPE_FETCH_REPLY_PARTIAL = 2;
TYPE_FETCH_REPLY_FINAL   = 3;
TYPE_FETCH_REPLY_EMPTY   = 4;


service = tolower(service) + mkbyte(0);
req = 
  mkbyte(1) +                          # version
  mkbyte(TYPE_FETCH_REQ) +             # message type
  mkword(strlen(service)+10) +         # total length
  mkword(9) +                          # service type
  mkword(strlen(service)) +            # name length
  mkword(0) +                          # sig length
  service;  
send(socket:soc, data:req);

res = recv(socket:soc, length:1024, min:10);
close(soc);


# If...
if (
  strlen(res) >= 10 &&
  # the message type indicates a reply and ...
  (
    getbyte(blob:res, pos:1) == TYPE_FETCH_REPLY_FINAL || 
    getbyte(blob:res, pos:1) == TYPE_FETCH_REPLY_EMPTY
  ) &&
  # the packet size agrees with the word at offset 2 and...
  getword(blob:res, pos:2) == strlen(res) &&
  # the word at offset 4 is 9
  getword(blob:res, pos:4) == 9 &&
  # the service name length agrees with the word at offset 6 and
  getword(blob:res, pos:6) == strlen(service) &&
  # the service name we requested is located at offset 10.
  stridx(res, service) == 10
)
{
  # Register and report the service.
  register_service(port:port, ipproto:"udp", proto:"notary");
  security_note(port:port, proto:"udp");
}
