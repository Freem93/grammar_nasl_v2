#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42087);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/08/01 17:28:23 $");

  script_name(english:"POP3 Service STLS Command Support");
  script_summary(english:"Checks if service supports STLS");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote mail service supports encrypting traffic."
  );
  script_set_attribute( attribute:"description",  value:
"The remote POP3 service supports the use of the 'STLS' command to
switch from a cleartext to an encrypted communications channel."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://en.wikipedia.org/wiki/STARTTLS"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://tools.ietf.org/html/rfc2595"
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/09");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/pop3", 110);

  exit(0);
}


include("global_settings.inc");
include("pop3_func.inc");
include("x509_func.inc");


port = get_service(svc:"pop3", default:110, exit_on_fail:TRUE);

encaps = get_kb_item("Transports/TCP/"+port);
if (encaps && encaps > ENCAPS_IP) exit(0, "The POP3 server on port "+port+" always encrypts traffic.");


soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket on port "+port+".");

s = recv_line(socket:soc, length:2048);
if (!strlen(s)) 
{
  close(soc);
  exit(1, "Failed to receive a banner from the POP3 server on port "+port+".");
}

c = "STLS";
send(socket:soc, data:c+'\r\n');

resp = "";
while (s = recv_line(socket:soc, length:2048))
{
  s = chomp(s);
  match = eregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
  if (!isnull(match))
  {
    resp = match[1];
    break;
  }
}
if (resp) set_kb_item(name:"pop3/"+port+"/starttls_tested", value:TRUE);

if (resp && "+OK" == toupper(resp))
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
        'Here is the POP3 server\'s SSL certificate that Nessus was able to\n' +
        'collect after sending a \'STLS\' command :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        info +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
    }
    else
    {
      report = '\n' +
        'The remote POP3 service responded to the \'STLS\' command with an\n' +
        "'" + resp + "' response code, suggesting that it supports that command. However," + '\n' +
        'Nessus failed to negotiate a TLS connection or get the associated SSL\n' +
        'certificate, perhaps because of a network connectivity problem or the\n' +
        'service requires a peer certificate as part of the negotiation.';
    }
    if (COMMAND_LINE) display(report);
    else security_note(port:port, extra:report);
  }
  else security_note(port);

  set_kb_item(name:"pop3/"+port+"/starttls", value:TRUE);

  # nb: we haven't actually completed the SSL handshake so just bail.   
  close(soc);
  exit(0);
}

# Be nice and logout.
c = "QUIT";
send(socket:soc, data:c+'\r\n');

resp = "";
while (s = recv_line(socket:soc, length:2048))
{
  s = chomp(s);
  match = eregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
  if (!isnull(match))
  {
    resp = match[1];
    break;
  }
}
close(soc);
