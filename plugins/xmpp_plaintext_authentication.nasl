#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(87736);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/01/05 18:44:51 $");

  script_name(english:"XMPP Cleartext Authentication");
  script_summary(english:"Checks for cleartext authentication support.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a service that allows cleartext
authentication.");
  script_set_attribute(attribute:"description", value:
"The remote Extensible Messaging and Presence Protocol (XMPP) service
supports one or more authentication mechanisms that allow credentials
to be sent in the clear.");
  script_set_attribute(attribute:"solution", value:
"Disable cleartext authentication mechanisms in the XMPP configuration.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/05");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencie("xmpp_server_detect.nasl");
  script_require_ports(5222,"Services/jabber");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"jabber", default:5222);

if(get_port_transport(port) != ENCAPS_IP)
  audit(AUDIT_LISTEN_NOT_VULN, "XMPP", port);

if (!get_tcp_port_state(port))
  audit(AUDIT_PORT_CLOSED, port, "tcp");

soc = open_sock_tcp(port);

if(!soc) audit(AUDIT_SOCK_FAIL, port);

init_msg =
  "<?xml version='1.0' ?>" +
  "<stream:stream to='" + get_host_name() + 
  "' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' " +
  "version='1.0'>" + '\n';

send(socket:soc, data:init_msg);

response = recv(socket:soc, length:2048);

close(soc);

#<mechanism>PLAIN</mechanism>
#<mechanism>LOGIN</mechanism>
if(response =~ "<\s*mechanism\s*>\s*PLAIN\s*<" ||
   response =~ "<\s*mechanism\s*>\s*LOGIN\s*<")
{
  pci_report = 'The remote XMPP service accepts cleartext logins.';
  set_kb_item(name:"PCI/ClearTextCreds/" + port, value:pci_report);

  security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "XMPP", port); 
