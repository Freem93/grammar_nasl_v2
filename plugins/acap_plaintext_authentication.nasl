#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(87732);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/01/05 18:44:51 $");

  script_name(english:"ACAP Cleartext Authentication");
  script_summary(english:"Checks for cleartext authentication support.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a service that allows cleartext
authentication.");
  script_set_attribute(attribute:"description", value:
"The remote Automated Content Access Protocol (ACAP) service supports
one or more authentication mechanisms that allow credentials to be
sent in the clear.");
  script_set_attribute(attribute:"solution", value:
"Disable cleartext authentication mechanisms in the ACAP configuration.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/05");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("find_service_3digits.nasl", "doublecheck_std_services.nasl");
  script_require_ports("Services/acap");

  exit(0);
}

include("misc_func.inc");
include("global_settings.inc");
include("audit.inc");

port = get_service(svc:"acap", default:674);

if(get_port_transport(port) != ENCAPS_IP)
  audit(AUDIT_LISTEN_NOT_VULN, "ACAP", port);

if (!get_tcp_port_state(port))
  audit(AUDIT_PORT_CLOSED, port, "tcp");

soc = open_sock_tcp(port);
banner = recv(socket:soc, length:2048);
close(soc);

item = eregmatch(pattern : "\(\s*SASL\s+([^\)]+)\)",
                 string  : banner);

if(isnull(item) || isnull(item[1]))
  exit(0, "Unable to enumerate any SASL mechanisms for ACAP service on port " + port + ".");

bad_mechs = make_list();

mechs = str_replace(string: item[1], find:'"', replace:'');

foreach mech (split(mechs, sep:' ', keep:FALSE))
{
  if(mech == 'PLAIN')
    bad_mechs = make_list(bad_mechs, 'PLAIN');
  if(mech ==  'LOGIN')
    bad_mechs = make_list(bad_mechs, 'LOGIN');
}

if(max_index(bad_mechs) > 0)
{
  pci_report = 'The remote ACAP service accepts cleartext logins.';
  set_kb_item(name:"PCI/ClearTextCreds/" + port, value:pci_report);

  report = '\n  Server supported SASL mechanisms : ' + mechs +
           '\n  Cleartext mechanisms supported   : ' + join(bad_mechs, sep:" ") + '\n';
  security_warning(port:port, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "ACAP", port); 
