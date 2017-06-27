#
# (C) Tenable Network Security, Inc.
#
#

include("compat.inc");

if (description)
{
  script_id(64814);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/01/19 15:18:17 $");

  script_name(english:"Terminal Services Use SSL/TLS");
  script_summary(english:"Checks if remote Terminal Services uses SSL/TLS");

  script_set_attribute(attribute:"synopsis", value:"The remote Terminal Services use SSL/TLS.");
  script_set_attribute(attribute:"description", value:"The remote Terminal Services is configured to use SSL/TLS.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:remote_desktop_protocol");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("windows_terminal_services.nasl");
  script_require_ports("Services/msrdp", 3389);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("x509_func.inc");

RDP_NEG_REQ     = 1;
RDP_NEG_RSP     = 2;
RDP_NEG_ERR     = 3;

SEC_PROTO_RDP       = 0;  # standard RDP security protocol
SEC_PROTO_SSL       = 1;  # TLS version 1
SEC_PROTO_HYBRID    = 2;  # Network Level Authentication (NLA), which also uses SSL

port = get_service(svc:'msrdp', default:3389, exit_on_fail:TRUE);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

s = open_sock_tcp(port,transport: ENCAPS_IP);
if(! s) audit(AUDIT_SOCK_FAIL, port,'TCP');

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

# request SSL or NLA
send(socket:s, data:
  # TPKT Header [T.123]
  '\x03' + # version number (always 0000 0011)
  '\x00' + # reserved (always 0)
  '\x00\x13' + # Length (including header) - big endian

  # Connection request TPDU
  '\x0e' + # LI (length indicator)
  '\xe0' + # CR (1110) + CDT (0000 = class 0 or 1)
  '\x00\x00' + # DST REF (always 0)
  '\x00\x00' + # SRC REF
  '\x00' + # Class option (class 0)

  # RDP negotiation request
  mkbyte(RDP_NEG_REQ) + # Type (must be 1)
  '\x00' + # Flags (must be 0)
  '\x08\x00' + # Length (must be 8) - little endian
  mkdword(SEC_PROTO_HYBRID | SEC_PROTO_SSL)
);

data = recv(socket:s, length:19, timeout:60);
if(isnull(data))
  audit(code:1, AUDIT_RESP_NOT, port); 

# RDP server that supports security protocol negotiation must return a 19-byte response per protocol spec
if(strlen(data) != 0x13)
  audit(code:1, AUDIT_RESP_BAD, port, 'a RDP connection request: Unexpected length in response, the remote server may not support security protocol negotiation');

# TPKT Header [T.123]
if(getbyte(blob:data, pos:0) != 3) # Version (must be 3)
  audit(code:1, AUDIT_RESP_BAD, port, 'a RDP connection request: Unexpected TPKT version in response');
if(getbyte(blob:data, pos:1) != 0) # Reserved (must be 0)
  audit(code:1, AUDIT_RESP_BAD, port, 'a RDP connection request: Unexpected TPKT reserved field in response');

if(getword(blob:data, pos:2) != 0x1300) # Length (big endian)
  audit(code:1, AUDIT_RESP_BAD, port, 'a RDP connection request: Unexpected TPKT length in response');

# Ignore the LI, CR, CDT, DST REF, SRC REF, and Class Option
type  = getbyte(blob:data, pos:0x0b);
len   = getword(blob:data, pos: 0xd);
data  = getdword(blob:data, pos: 0xf);

if(len != 8)
 audit(code:1, AUDIT_RESP_BAD, port, 'a RDP connection request: Unexpected length in protocol negotiation response');

# successful response
if(type == RDP_NEG_RSP)
{
  # We requested SEC_PROTO_SSL|SEC_PROTO_HYBRID, and should get either one of them
  if (data != SEC_PROTO_SSL && data != SEC_PROTO_HYBRID)
    audit(code:1, AUDIT_RESP_BAD, port, 'a RDP connection request: Unexpected RDP security protocol negotiation response');
}
# error response
else if(type == RDP_NEG_ERR)
{
  if(data == 2)
    exit(0, 'The service listening on port '+port+' is configured to only use Standard RDP security protocol.');
  else if (data == 3)
    exit(0, 'The service listening on port '+port+' does not possess a valid certificate for a SSL connection.');
  else
    exit(0, 'The service listening on port '+port+' does not support SSL, code:'+data+
            '. See section 2.2.1.2.2 of [MS-RDPBCGR] for details.');
}
# unexpected response
else audit(code:1, AUDIT_RESP_BAD, port, 'a RDP connection request: Unexpected security protocol negotiation response type');

#
# RDP does support STARTTLS-style SSL
#
set_kb_item(name:"rdp/"+port+"/starttls", value:TRUE);

# Get and process the SSL certificate from the RDP server
cert = get_server_cert(port: port,encaps:ENCAPS_TLSv1,socket:s, encoding:"der");
close(s);
if (isnull(cert)) exit(1, "Failed to read the certificate for the service listening on port "+port+".");

cert = parse_der_cert(cert:cert);
if (isnull(cert)) exit(1, "Failed to parse the certificate from the service listening on port "+port+".");

report = dump_certificate(cert:cert);
if (!report) exit(1, "Failed to dump the certificate from the service listening on port "+port+".");

if (report_verbosity > 0) security_note(port:port, extra:report);
else security_note(port);
