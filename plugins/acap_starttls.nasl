#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42084);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/04/27 14:49:38 $");

  script_name(english:"ACAP Service STARTTLS Command Support");
  script_summary(english:"Checks if service supports STARTTLS");

  script_set_attribute(attribute:"synopsis", value:"The remote service supports encrypting traffic.");
  script_set_attribute(attribute:"description", value:
"The remote ACAP service supports the use of the 'STARTTLS' command to
switch from a cleartext to an encrypted communications channel.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/STARTTLS");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc2595");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("find_service_3digits.nasl", "doublecheck_std_services.nasl");
  script_require_ports("Services/acap", 674);

  exit(0);
}

include("acap_func.inc");
include("global_settings.inc");
include("x509_func.inc");

port = get_kb_item("Services/acap");
if (!port) port = 674;
if (!get_port_state(port)) exit(0, "TCP port "+port+" is closed.");

encaps = get_kb_item("Transports/TCP/"+port);
if (encaps && encaps > ENCAPS_IP) exit(0, "The ACAP server on port "+port+" always encrypts traffic.");

# Open a connection to the ACAP server.
soc = acap_open(port:port);
if (!soc) exit(1, "TCP connection failed to port " + port + ".");

# Send a STARTTLS command.
ret = acap_starttls(socket:soc, dont_read_banner:TRUE);
if (!ret)
{
  close(soc);
  exit(1, "The ACAP server on port" + port + " didn't accept our STARTTLS command.");
}
soc = ret;
set_kb_item(name:"acap/" + port + "/starttls", value:TRUE);

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
      "Here is the ACAP server's SSL certificate that Nessus was able to\n",
      "collect after sending a 'STARTTLS' command :\n",
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
      "The remote ACAP service responded to the 'STARTTLS' command with an\n",
      "'OK' response, suggesting that it supports that command.  However,\n",
      "Nessus failed to negotiate a TLS connection or get the associated SSL\n",
      "certificate, perhaps because of a network connectivity problem or the\n",
      "service requires a peer certificate as part of the negotiation."
    );
  }
  if (COMMAND_LINE) display(report);
  else security_note(port:port, extra:report);
}
else security_note(port);

# nb: we haven't actually completed the SSL handshake so just bail.
close(soc);
