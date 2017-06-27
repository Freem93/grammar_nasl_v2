#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42149);
  script_version("$Revision: 1.9 $");

  script_name(english:"FTP Service AUTH TLS Command Support");
  script_summary(english:"Checks if service supports STARTTLS");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote directory service supports encrypting traffic."
  );
  script_set_attribute( attribute:"description",  value:
"The remote FTP service supports the use of the 'AUTH TLS' command to
switch from a cleartext to an encrypted communications channel."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://en.wikipedia.org/wiki/STARTTLS"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://tools.ietf.org/html/rfc4217"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"n/a"
  );
  script_set_attribute(
    attribute:"risk_factor", 
    value:"None"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/10/15"
  );
 script_cvs_date("$Date: 2017/05/16 19:35:39 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("global_settings.inc");
include("ftp_func.inc");
include("x509_func.inc");


port = get_ftp_port(default:21);

encaps = get_kb_item("Transports/TCP/"+port);
if (encaps && encaps > ENCAPS_IP) exit(0, "The FTP server on port "+port+" always encrypts traffic.");


soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket on port "+port+".");

s = ftp_recv_line(socket:soc);
if (!strlen(s))
{
  close(soc);
  exit(1, "Failed to receive a banner from the FTP server on port "+port+".");
}


c = "AUTH TLS";
s = ftp_send_cmd(socket:soc, cmd:c);
if (strlen(s) < 4) 
{
  ftp_close(socket:soc);

  if (strlen(s)) errmsg = string("The FTP server on port "+port+" sent an invalid response (", s, ").");
  else errmsg = string("Failed to receive a response from the FTP server on port ", port, ".");
  exit(1, errmsg);
}
resp = substr(s, 0, 2);

if (resp && resp == "234")
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
      report = string(
        "\n",
        "Here is the FTP server's SSL certificate that Nessus was able to\n",
        "collect after sending a 'AUTH TLS' command :\n",
        "\n",
        crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
        info,
        crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
      );
    }
    else
    {
      report = string(
        "\n",
        "The remote FTP service responded to the 'AUTH TLS' command with a\n",
        "'", resp, "' response code, suggesting that it supports that command.  However,\n",
        "Nessus failed to negotiate a TLS connection or get the associated SSL\n",
        "certificate, perhaps because of a network connectivity problem or the\n",
        "service requires a peer certificate as part of the negotiation."
      );
    }
    if (COMMAND_LINE) display(report);
    else security_note(port:port, extra:report);
  }
  else security_note(port);

  set_kb_item(name:"ftp/"+port+"/starttls", value:TRUE);

  # nb: we haven't actually completed the SSL handshake so just bail.   
  close(soc);
  exit(0);
}
ftp_close(socket:soc);
