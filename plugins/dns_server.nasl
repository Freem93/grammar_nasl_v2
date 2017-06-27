#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11002);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2017/05/16 19:35:38 $");

 script_name(english:"DNS Server Detection");
 script_summary(english:"Detects a running name server");

 script_set_attribute(attribute:"synopsis", value:"A DNS server is listening on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote service is a Domain Name System (DNS) server, which
provides a mapping between hostnames and IP addresses.");
 script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Domain_Name_System");
 script_set_attribute(attribute:"solution", value:
"Disable this service if it is not needed or restrict access to
internal hosts only if the service is available externally.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/02/13");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_family(english:"DNS");

 exit(0);
}

#
# We ask the nameserver to resolve 127.0.0.1
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("dns_func.inc");
include("byte_func.inc");

dns["transaction_id"] = rand() % 65535;
dns["flags"]	      = 0x0010;
dns["q"]	      = 1;

packet = mkdns(
           dns:dns,
           query:mk_query(
             txt:dns_str_to_query_txt("1.0.0.127.IN-ADDR.ARPA"),
             type:DNS_QTYPE_PTR,
             class:DNS_QCLASS_IN
           )
         );

dns_found = FALSE;

if (get_udp_port_state(53))
{
  soc = open_sock_udp(53);
  if ( soc )
  {
    send(socket:soc, data:packet);
    r = recv(socket:soc, length:1024);

    if (strlen(r) > 3)
    {
      flags = ord(r[2]);
      if (flags & 0x80)
      {
        dns_found = TRUE;
 	security_note(port:53, protocol:"udp");
	set_kb_item(name:"DNS/udp/53", value:TRUE);
	register_service(port:53, proto: "dns", ipproto:"udp");
      }
    }
  }
}

if (get_port_state(53))
{
  soc = open_sock_tcp(53);
  if (!soc) audit(AUDIT_SOCK_FAIL, 53);

  req = mkword(strlen(packet)) + packet;
  send(socket:soc, data:req);

  r = recv(socket:soc, length:2, min:2);
  if (strlen(r) == 2)
  {
   len = getword(blob:r, pos:0);
   if (len > 128) len = 128;
   r = recv(socket:soc, length:len, min:len);

   if (strlen(r) > 3)
   {
     flags = ord(r[2]);
     if (flags & 0x80)
     {
       dns_found = TRUE;
       set_kb_item(name:"DNS/tcp/53", value:TRUE);
       security_note(53);
       register_service(port:53, proto:"dns");
      }
    }
  }
}

if (!dns_found) audit(AUDIT_NOT_LISTEN, "DNS", 53);
