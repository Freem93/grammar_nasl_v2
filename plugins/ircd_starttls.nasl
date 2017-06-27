#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87817);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_name(english:"IRC Daemon STARTTLS Command Support");
  script_summary(english:"Checks if service supports STARTTLS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote IRC daemon supports the encryption of traffic.");
  script_set_attribute(attribute:"description", value:
"The remote IRC daemon supports the use of the 'STARTTLS' command to
switch from a cleartext to an encrypted communications channel.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/STARTTLS");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc7194");
  script_set_attribute(attribute:"see_also", value:"https://wiki.inspircd.org/STARTTLS_Documentation");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencie("ircd.nasl");
  script_require_ports("Services/irc", 6667);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("x509_func.inc");

port = get_service(svc:"irc", default:6667, exit_on_fail:TRUE);

encaps = get_kb_item("Transports/TCP/"+port);
if (encaps && encaps > ENCAPS_IP) exit(0, "The IRC daemon on port "+port+" always encrypts traffic.");

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

req = 'STARTTLS\r\n';
send(socket:soc, data:req);

resp = "";
while(s = recv_line(socket:soc, length:2048))
{
  s = chomp(s);
  # 670 is STARTTLS success
  # 691 is explicit STARTTLS failure/not supported
  # no response is STARTTLS not supported
  if(s =~ "^[^ ]+ (670|691) ")
  {
    resp = s;
    break;
  }
}

if (resp && resp =~ "^[^ ]+ 670 ")
{
  # nb: call get_server_cert() regardless of report_verbosity so
  #     the cert will be saved in the KB.
  cert = get_server_cert(
    port     : port,
    socket   : soc,
    encoding : "der",
    encaps   : ENCAPS_TLSv1
  );
  if (report_verbosity > 0)
  {
    info = "";

    cert = parse_der_cert(cert:cert);
    if (!isnull(cert)) info = dump_certificate(cert:cert);

    if (info)
    {
      report = '\n' +
        'Here is the IRC server\'s SSL certificate that Nessus was able to\n' +
        'collect after sending a \'STARTTLS\' command :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        info +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
    }
    else
    {
      report = '\n' +
        'The remote IRC service responded to the \'STARTTLS\' command with a\n' +
        "670 response code, suggesting that it supports that command. However," + '\n' +
        'Nessus failed to negotiate a TLS connection or get the associated SSL\n' +
        'certificate, perhaps because of a network connectivity problem or the\n' +
        'service requires a peer certificate as part of the negotiation.\n';
    }
    if (COMMAND_LINE) display(report);
    else security_note(port:port, extra:report);
  }
  else security_note(port);

  set_kb_item(name:"irc/"+port+"/starttls", value:TRUE);

  # nb: we haven't actually completed the SSL handshake so just bail.
  close(soc);
  exit(0);
}

# Be nice and logout.
c = "QUIT";
send(socket:soc, data:c+'\r\n');

while (s = recv_line(socket:soc, length:2048));
close(soc);
