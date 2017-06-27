#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51890);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/06/23 19:16:51 $");

  script_name(english:"Telnet Service START_TLS Support");
  script_summary(english:"Checks if service supports START_TLS");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote telnet service supports encrypting traffic."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Telnet service supports the use of a 'START_TLS' option to
switch from a cleartext to an encrypted communications channel."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://en.wikipedia.org/wiki/STARTTLS"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://tools.ietf.org/id/draft-altman-telnet-starttls-02.txt"
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/07");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencie("find_service1.nasl");
  script_require_ports("Services/telnet", 23);

  exit(0);
}


include("global_settings.inc");
include("telnet2_func.inc");
include("x509_func.inc");


port = get_service(svc:"telnet", default:23, exit_on_fail:TRUE);

encaps = get_kb_item("Transports/TCP/"+port);
if (encaps && encaps > ENCAPS_IP) exit(0, "The Telnet server on port "+port+" always encrypts traffic.");


soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket on port "+port+".");


if (telnet_starttls(socket:soc))
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
      report = 
        '\n' + 'Here is the Telnet server\'s SSL certificate that Nessus was able to' +
        '\n' + 'collect after using a \'START_TLS\' option to negotiate an encrypted' +
        '\n' + 'connection :' +
        '\n' +
        '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) +
        '\n' + info +
        '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
    }
    else
    {
      report = 
        '\n' + 'The remote Telnet service responded to a \'START_TLS\' option in a' +  
        '\n' + 'way that suggests it supports that option.  However, Nessus failed' +
        '\n' + 'get the associated SSL certificate, perhaps because of a network' +
        '\n' + 'connectivity problem or the service requires a peer certificate as' +
        '\n' + 'part of the negotiation.';   
    }
    if (COMMAND_LINE) display(report);
    else security_note(port:port, extra:report);
  }
  else security_note(port);

  set_kb_item(name:"telnet/"+port+"/starttls", value:TRUE);
}
close(soc);
