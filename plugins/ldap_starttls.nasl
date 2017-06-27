#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42329);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_name(english:"LDAP Service STARTTLS Command Support");
  script_summary(english:"Checks if service supports STARTTLS");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote directory service supports encrypting traffic."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote LDAP service supports the use of the 'STARTTLS' command to
switch from a cleartext to an encrypted communications channel."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://en.wikipedia.org/wiki/STARTTLS"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://tools.ietf.org/html/rfc2830"
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
    value:"2009/10/30"
  );
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencie("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}


include("global_settings.inc");
include("ldap_func.inc");
include("x509_func.inc");


port = get_kb_item("Services/ldap");
if (!port) port = 389;
if (!get_port_state(port)) exit(1, "Port "+port+" is closed.");

encaps = get_kb_item("Transports/TCP/"+port);
if (encaps && encaps > ENCAPS_IP) exit(0, "The LDAP server on port "+port+" always encrypts traffic.");


soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket on port "+port+".");

ldap_init(socket:soc);

req = ldap_extended_request(oid:'1.3.6.1.4.1.1466.20037');
res = ldap_request_sendrecv(data:req);
if (isnull(res))
{
  close(soc);
  exit(1, "The LDAP server on port "+port+" didn't respond.");
}
if (res[0] != LDAP_EXTENDED_RESPONSE)
{
  close(soc);
  exit(1, "The LDAP server on port "+port+" sent an unexpected response code ("+res[0]+".");
}

ext_res = ldap_parse_extended_response(data:res[1]);
if (isnull(ext_res))
{
  close(soc);
  exit(1, "Unknown error ("+ldap_get_last_error()+") parsing the extended response from the LDAP server on port "+port+".");
}

if (ext_res[0] == 0)
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
        "Here is the LDAP server's SSL certificate that Nessus was able to\n",
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
        "The remote LDAP service responded to the 'STARTTLS' command with a\n",
        "result code that suggests it supports that command.  However, Nessus\n",
        "failed to negotiate a TLS connection or get the associated SSL\n",
        "certificate, perhaps because of a network connectivity problem or the\n",
        "service requires a peer certificate as part of the negotiation."
      );
    }
    if (COMMAND_LINE) display(report);
    else security_note(port:port, extra:report);
  }
  else security_note(port);

  set_kb_item(name:"ldap/"+port+"/starttls", value:TRUE);
}
close(soc);
