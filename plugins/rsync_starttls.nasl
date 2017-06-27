#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87818);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/01/08 15:38:43 $");

  script_name(english:"rsync STARTTLS Command Support");
  script_summary(english:"Checks if the service supports STARTTLS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote synchronization service supports the encryption of
traffic.");
  script_set_attribute(attribute:"description", value:
"The remote rsync server supports the use of the '#starttls' command to
switch from a cleartext to an encrypted communications channel.");
  script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Rsync");
  script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/STARTTLS");
  script_set_attribute(attribute:"see_also", value:"http://metastatic.org/source/rsync-ssl.patch");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/rsyncd", 873);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rsync.inc");
include("x509_func.inc");

port = get_service(svc:"rsyncd", default:873, exit_on_fail:TRUE);

encaps = get_kb_item("Transports/TCP/"+port);
if (encaps && encaps > ENCAPS_IP) exit(0, "The rsync service on port "+port+" always encrypts traffic.");

soc = rsync_init(port:port, exit_if_fail:TRUE);

req = '#starttls\r\n';
send(socket:soc, data:req);

res = recv_line(socket:soc, length:255);
if (res =~ "^@RSYNCD: starttls")
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
        'Here is the rsync server\'s SSL certificate that Nessus was able to\n' +
        'collect after sending a \'#starttls\' command :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        info +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
    }
    else
    {
      report = '\n' +
        'The remote rsync service responded to the \'#starttls\' command with a\n' +
        "@RSYNCD response code, suggesting that it supports that command. However," + '\n' +
        'Nessus failed to negotiate a TLS connection or get the associated SSL\n' +
        'certificate, perhaps because of a network connectivity problem or the\n' +
        'service requires a peer certificate as part of the negotiation.\n';
    }
    if (COMMAND_LINE) display(report);
    else security_note(port:port, extra:report);
  }
  else security_note(port);

  set_kb_item(name:"rsyncd/"+port+"/starttls", value:TRUE);
}

close(soc);
