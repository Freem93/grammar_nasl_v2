#
# (C) Tenable Network Security, Inc.
#

# Revised 19/02/05 by Martin O'Neal of Corsaire to make the detection more positive, include the
#                  correct CVE and to update the knowledgebase appropriately
#

include("compat.inc");

if(description)
{
  script_id(11819);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/02/22 17:47:58 $");

  script_name(english:"TFTP Daemon Detection");
  script_summary(english:"Attempts to retrieve a nonexistent file.");

  script_set_attribute(attribute:"synopsis", value:
"A TFTP server is listening on the remote port.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a TFTP (Trivial File Transfer Protocol)
daemon. TFTP is often used by routers and diskless hosts to retrieve
their configuration. It can also be used by worms to propagate.");
  script_set_attribute(attribute:"solution", value:
"Disable this service if you do not use it.");
  script_set_attribute(attribute:"risk_factor", value:"None" );

  script_set_attribute(attribute:"plugin_publication_date", value: "2003/08/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

  script_dependencies("external_svc_ident.nasl", "find_service1.nasl");
  script_require_udp_ports(69);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

if ( islocalhost() ) audit(AUDIT_LOCALHOST);

service = "tftpd";

port = 69;

if (!service_is_unknown(port:port, ipproto: 'udp'))
  audit(AUDIT_SVC_KNOWN);

soc = open_sock_udp(port);
if(!soc)
  audit(AUDIT_SOCK_FAIL, port);

file = string("nessus" + rand());

foreach mode (make_list("netascii", "octet"))
{
  data = raw_string(0x00, 0x01) + file + raw_string(0x00) + mode + raw_string(0x00);

  # Some backdoors never return "file not found"
  # filter = 'udp and dst port 4315 and src host ' + get_host_ip() + ' and udp[9:1]=0x05';
  filter = 'udp and src host ' + get_host_ip() + ' and udp[8:1]=0x00';

  rep = NULL;
  for ( i = 0 ; i < 3 ; i ++ )
  {
    rep = send_capture(socket:soc, data:data, pcap_filter:filter, timeout:1);
    if ( rep ) break;
  }
  if ( rep ) break;
}

close(soc);

if( rep )
{
  data = get_udp_element(udp:rep, element:"data");

  if(data[0] == '\0' && (data[1] == '\x03' || data[1] == '\x05'))
  {
    security_note(port:port, proto:"udp");
    register_service(port: port, ipproto: 'udp', proto: service);
    exit(0);
  }
  else audit(AUDIT_NOT_DETECT, service, port);
}
else audit(AUDIT_NOT_DETECT, service, port);
