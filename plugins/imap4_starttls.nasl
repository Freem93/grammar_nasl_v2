#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42085);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_name(english:"IMAP Service STARTTLS Command Support");
  script_summary(english:"Checks if service supports STARTTLS");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote mail service supports encrypting traffic."
  );
  script_set_attribute( attribute:"description",  value:
"The remote IMAP service supports the use of the 'STARTTLS' command to
switch from a cleartext to an encrypted communications channel."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://en.wikipedia.org/wiki/STARTTLS"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://tools.ietf.org/html/rfc2595"
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/09");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("global_settings.inc");
include("imap_func.inc");
include("x509_func.inc");


port = get_service(svc:"imap", default:143, exit_on_fail:TRUE);

encaps = get_kb_item("Transports/TCP/"+port);
if (encaps && encaps > ENCAPS_IP) exit(0, "The IMAP server on port "+port+" always encrypts traffic.");


soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket on port "+port+".");

s = recv_line(socket:soc, length:2048);
if (!strlen(s))
{
  close(soc);
  exit(1, "Failed to receive a banner from the IMAP server on port"+port+".");
}
tag = 0;


++tag;
c = "nessus" + tag + " STARTTLS";
send(socket:soc, data:c+'\r\n');

resp = "";
while (s = recv_line(socket:soc, length:2048))
{
  s = chomp(s);
  match = eregmatch(pattern:"^nessus"+tag+" (OK|BAD|NO)", string:s, icase:TRUE);
  if (!isnull(match))
  {
    resp = match[1];
    break;
  }
}

if (resp && "OK" == toupper(resp))
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
        'Here is the IMAP server\'s SSL certificate that Nessus was able to\n' +
        'collect after sending a \'STARTTLS\' command :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        info +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
    }
    else
    {
      report = '\n' +
        'The remote IMAP service responded to the \'STARTTLS\' command with an\n' +
        "'" + resp + "' response code, suggesting that it supports that command. However," + '\n' +
        'Nessus failed to negotiate a TLS connection or get the associated SSL\n' +
        'certificate, perhaps because of a network connectivity problem or the\n' +
        'service requires a peer certificate as part of the negotiation.';
    }
    if (COMMAND_LINE) display(report);
    else security_note(port:port, extra:report);
  }
  else security_note(port);

  set_kb_item(name:"imap/"+port+"/starttls", value:TRUE);

  # nb: we haven't actually completed the SSL handshake so just bail.
  close(soc);
  exit(0);
}


# Be nice and logout.
++tag;
c = "nessus" +tag +" LOGOUT";
send(socket:soc, data:c+'\r\n');

resp = "";
while (s = recv_line(socket:soc, length:2048))
{
  s = chomp(s);
  match = eregmatch(pattern:"^nessus"+tag+" (OK|BAD|NO)", string:s, icase:TRUE);
  if (!isnull(match))
  {
    resp = match[1];
    break;
  }
}
close(soc);
