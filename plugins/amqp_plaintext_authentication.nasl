#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87733);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/01/05 18:44:51 $");

  script_name(english:"AMQP Cleartext Authentication");
  script_summary(english:"Checks for cleartext authentication support.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a service that allows cleartext
authentication.");
  script_set_attribute(attribute:"description", value:
"The remote Advanced Message Queuing Protocol (AMQP) service supports
one or more authentication mechanisms that allow credentials to be
sent in the clear.");
  script_set_attribute(attribute:"solution", value:
"Disable cleartext authentication mechanisms in the AMQP configuration.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/05");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("amqp_detect.nasl");
  script_require_ports("Services/amqp", 5671, 5672);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "Advanced Message Queuing Protocol";

# Get the ports that AMQP has been found on.
port = get_service(svc:"amqp", default:5672, exit_on_fail:TRUE);

if(get_port_transport(port) != ENCAPS_IP)
  audit(AUDIT_LISTEN_NOT_VULN, app, port);

# Connect to the port.
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

# All parameters are big-endian.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

kb = "amqp/" + port + "/";
tmp = get_kb_item_or_exit(kb + "protocol/version");
ver = split(tmp, sep:".", keep:FALSE);

magic = "AMQP";
req = raw_string(
  magic, # Magic cookie
  0,     # Protocol ID
  int(ver[0]), # Major version number
  int(ver[1]), # Minor version number
  int(ver[2])  # Revision number
);

# Send the request and hope for an AMQP response.
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);

if("PLAIN" >< res || "LOGIN" >< res)
{
  pci_report = 'The remote AMQP service accepts cleartext logins.';
  set_kb_item(name:"PCI/ClearTextCreds/" + port, value:pci_report);

  security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port); 
