#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23777);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2011/03/06 02:08:27 $");

  script_name(english:"SLP Server Detection (TCP)");
  script_summary(english:"Detects an SLP server over tcp");

  script_set_attribute(attribute:"synopsis", value:
"The remote server supports the Service Location Protocol." );
  script_set_attribute(attribute:"description", value:
"The remote server understands Service Location Protocol (SLP), a
protocol that allows network applications to discover the existence,
location, and configuration of various services in an enterprise
network environment.  A server that understands SLP can either be a
service agent (SA), which knows the location of various services, or a
directory agent (DA), which acts as a central repository for service
location information." );
  script_set_attribute(attribute:"see_also", value:"http://www.ietf.org/rfc/rfc2608.txt" );
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired." );
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"plugin_publication_date", value: "2006/12/07");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 427);
  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  ) {
  port = get_unknown_svc(427);
  # This is a silent_service()
  if (!port) exit(0);
}
else port = 427;
if (known_service(port:port)) exit(0);
if (!get_tcp_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


flags = 0;
nxo = 0;                               # 0 => no extensions being used
xid = rand() % 0xffff;
lang = "en";
prlist = "";
svc_types = make_list(
  "service:service-agent",
  "service:directory-agent"
);
scope = "DEFAULT";
pred = "";
slp_spi = "";


# Send a service request.
info = "";
foreach svc (svc_types)
{
  pktlen = 24 + strlen(lang+prlist+svc+scope+pred+slp_spi);
  req = mkbyte(2) +                    # version (nb: no support for version 1)
    mkbyte(1) +                        # function (1 => service request)
    mkbyte(pktlen / 255) +             # packet length
      mkword(pktlen % 255) +
    mkword(flags) +                    # flags
    mkbyte(nxo / 255) +                # next extension offset
      mkword(nxo % 255) +
    mkword(xid) +                      # XID
    mkword(strlen(lang)) + lang +      # language tag
    mkword(strlen(prlist)) + prlist +  # previous responder list
    mkword(strlen(svc)) + svc +        # service type
    mkword(strlen(scope)) + scope +    # scope list
    mkword(strlen(pred)) + pred +      # predicate
    mkword(strlen(slp_spi)) + slp_spi; # SLP SPI

  # nb: Responses are sometimes sent via UDP; eg, NetWare.
  filter = string(
    "udp and ",
    "src host ", get_host_ip(), " and ",
    "src port ", port, " and ",
    "dst port ", get_source_port(soc)
  );
  res = send_capture(socket:soc, data:req, pcap_filter:filter);
  if (!res) res = recv(socket:soc, length:4096);

  # If ...
  if (
    # the string is long enough and ...
    strlen(res) > 10 && 
    # the SLP version is at least 2 and ...
    getbyte(blob:res, pos:0) >= 2
  )
  {
    # Determine whether it's a DA or an SA based on the type of response.
    fn = getbyte(blob:res, pos:1);
    if (fn == 8 && "service:directory-agent://" >< res)
    {
      info = "An SLP Directory Agent is listening on this port.";
      break;
    }
    else if (fn == 11 && "service:service-agent://" >< res)
    {
      info = "An SLP Service Agent is listening on this port.";
      break;
    }
    else if (fn == 2)
    {
      info = 'An SLP server is listening on this port, but Nessus was unable\n' +
             'to determine whether it was a Directory or a Service Agent.';
      # don't break -- we'll use this as a fall-back.
    }
  }
}


if (info)
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"slp");

  # Send a service type request to try to discover known services.
  #
  # nb: support for this is optional.
  xid += 1;
  pktlen = 20 + strlen(lang+prlist+scope);
  req = mkbyte(2) +                    # version (nb: no support for version 1)
    mkbyte(9) +                        # function (9 => service type request)
    mkbyte(pktlen / 255) +             # packet length
      mkword(pktlen % 255) +
    mkword(flags) +                    # flags
    mkbyte(nxo / 255) +                # next extension offset
      mkword(nxo % 255) +
    mkword(xid) +                      # XID
    mkword(strlen(lang)) + lang +      # language tag
    mkword(strlen(prlist)) + prlist +  # previous responder list
    mkword(0xffff) +                   # naming authority (0xffff => omitted)
    mkword(strlen(scope)) + scope;     # scope list

  # nb: UA's can send this using TCP.
  send(socket:soc, data:req);
  res = recv(socket:soc, length:1024);
  if (
    # the string is long enough and ...
    strlen(res) > 20 && 
    # the SLP version is at least 2 and ...
    getbyte(blob:res, pos:0) >= 2 && 
    # it's a Service Type Reply and ...
    getbyte(blob:res, pos:1) == 10
  )
  {
    svcs = split(substr(res, 20), sep:",", keep:FALSE);
    info += '\n' +
            '\n' +
            'In addition, Nessus was able to learn that the agent knows about\n' +
            'the following services :\n' +
            '\n';
    foreach svc (sort(svcs))
      info += '  ' + svc + '\n';
  }

  security_note(port:port, extra: '\n'+info);
}


close(soc);
