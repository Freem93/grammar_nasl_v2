#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62350);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/06/23 19:16:51 $");

  script_name(english:"Advanced Message Queuing Protocol Detection STARTTLS Support");
  script_summary(english:"Checks if service supports STARTTLS");

  script_set_attribute(attribute:"synopsis", value:
"The remote service supports encrypting traffic.");
  script_set_attribute(attribute:"description", value:
"The remote Advanced Message Queuing Protocol service supports the
'STARTTLS' command to switch from a cleartext to an encrypted
communications channel.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d2ae6f6");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("amqp_detect.nasl");
  script_require_ports("Services/amqp", 5671, 5672);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("x509_func.inc");

app = "Advanced Message Queuing Protocol";

# Get the ports that AMQP has been found on.
port = get_service(svc:"amqp", default:5672, exit_on_fail:TRUE);

# Find out if this port is unencapsulated.
encaps = get_kb_item("Transports/TCP/" + port);
if (encaps && encaps > ENCAPS_IP)
  exit(0, "The " + app + " server on port " + port + " always encrypts traffic.");

# Connect to the port.
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

# Send the STARTTLS command.
soc = amqp_starttls(socket:soc);
if (!soc) exit(1, "The " + app + " server on port " + port + " didn't accept our STARTTLS attempt.");
set_kb_item(name:"amqp/" + port + "/starttls", value:TRUE);

# Call get_server_cert() regardless of report_verbosity so the cert
# will be saved in the KB.
cert = get_server_cert(
  port     : port,
  socket   : soc,
  encoding : "der",
  encaps   : ENCAPS_TLSv1
);

# Clean up.
close(soc);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  info = "";

  cert = parse_der_cert(cert:cert);
  if (!isnull(cert)) info = dump_certificate(cert:cert);

  if (info)
  {
    snip = crap(data:"-", length:30) + " snip " + crap(data:"-", length:30);

    report = string(
      "\nHere is the " + app + " server's SSL certificate that Nessus",
      "\nwas able to collect after sending a StartTLS request :",
      "\n",
      "\n", snip,
      "\n", info,
      "\n", snip,
      "\n"
    );
  }
  else
  {
    report = string(
      "\nThe remote service responded to our StartTLS request with a positive",
      "\nresponse, suggesting that it supports that command. However, Nessus",
      "\nfailed to negotiate a TLS connection or get the associated SSL",
      "\ncertificate, perhaps because of a network connectivity problem or the",
      "\nservice requires a peer certificate as part of the negotiation.",
      "\n"
    );
  }
}

security_note(port:port, extra:report);
