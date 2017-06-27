#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42089);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/06/23 19:16:51 $");

  script_name(english:"XMPP Service STARTTLS Command Support");
  script_summary(english:"Checks if service supports STARTTLS");

  script_set_attribute(attribute:"synopsis", value:"The remote instant messaging service supports encrypting traffic.");
  script_set_attribute(attribute:"description", value:
"The remote XMPP (eXtensible Messaging and Presence Protocol) service
supports the use of the 'STARTTLS' command to switch from a cleartext
to an encrypted communications channel.");
  script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/STARTTLS");
  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc3920#section-5");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencie("xmpp_server_detect.nasl");
  script_require_ports("Services/jabber", 5222, "Services/jabber_s2s", 5269);

  exit(0);
}


include("global_settings.inc");
include("x509_func.inc");
include("xmpp_func.inc");


ports = get_kb_list("Services/jabber");
if (isnull(ports)) ports = make_list(5222);

foreach port (ports)
{
  if (!get_port_state(port)) continue;

  encaps = get_kb_item("Transports/TCP/"+port);
  if (encaps && encaps > ENCAPS_IP) continue;

  banner = get_kb_item("xmpp/" + port + "/banner");
  if (
    report_paranoia < 2 &&
    (
      "<stream:features" >!< banner ||
      "<starttls" >!< banner
    )
  ) continue;

  foreach mode (make_list("client", "server"))
  {
    soc = xmpp_open(port:port, mode:mode);
    if (isnull(soc)) continue;

    ret = xmpp_starttls(socket:soc, dont_read_banner:TRUE);
    if (isnull(ret))
    {
      close(soc);
      continue;
    }
    soc = ret;
    set_kb_item(name:"xmpp/" + port + "/starttls", value:TRUE);

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
          "Here is the XMPP service's SSL certificate that Nessus was able to\n",
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
          "The remote XMPP service responded to the 'STARTTLS' command with a\n",
          "'proceed' element, suggesting that it supports that command. However,\n",
          "Nessus failed to negotiate a TLS connection or get the associated SSL\n",
          "certificate, perhaps because of a network connectivity problem or the\n",
          "service requires a peer certificate as part of the negotiation."
        );
      }
      if (COMMAND_LINE) display(report);
      else security_note(port:port, extra:report);
    }
    else security_note(port);

    close(soc);
  }
}
