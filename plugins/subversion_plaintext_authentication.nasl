#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(87735);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/01/05 18:44:51 $");

  script_name(english:"Subversion Cleartext Authentication");
  script_summary(english:"Checks for cleartext authentication support.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a service that allows cleartext
authentication.");
  script_set_attribute(attribute:"description", value:
"The remote Subversion (SVN) service supports one or more
authentication mechanisms that allow credentials to be sent in the
clear.");
  script_set_attribute(attribute:"solution", value:
"Disable cleartext authentication mechanisms in the Subversion
configuration.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/05");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencie("subversion_detection.nasl");
  script_require_ports(3690,"Services/subversion");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"subversion", default:3690);

# Looks like TLS connections for SVN RA protocol is not supported,
# but check anyway for future proofing
if(get_port_transport(port) != ENCAPS_IP)
  audit(AUDIT_LISTEN_NOT_VULN, "SVN", port);

if (!get_tcp_port_state(port))
  audit(AUDIT_PORT_CLOSED, port, "tcp");

soc = open_sock_tcp(port);

if(!soc) audit(AUDIT_SOCK_FAIL, port);

greeting = recv(socket:soc, length:2048);

# ( success ( 2 2 ( 
item = eregmatch(pattern:"^\(\s+success\s+\(\s+(\d+)\s+(\d+)\s+\(", string:greeting);

if(isnull(item))
{
  close(soc);
  exit(1, "Error parsing server greeting for SVN service on port " + port + ".");
}

min_ver = int(item[1]);
max_ver = int(item[2]);

if(min_ver > 2 || max_ver < 2)
   exit(0, "Unsupported SVN remote version range (min:" + min_ver + ", max:" + max_ver + ")");

url = "svn://" + get_host_name();

greeting_response =
"( " +
  "2 " + # version
  "( edit-pipeline ) " + # capabilities
  strlen(url) + ":" + url + " " +
  "6:Nessus " + # ra-client
  "( ) " + # client
")" + '\n';

send(socket:soc, data:greeting_response);

auth_request = recv(socket:soc, length:2048);

close(soc);
#(
#  success
#  (  # auth-request
#    (PLAIN LOGIN DIGEST-MD5) # SASL Mechs
item = eregmatch(pattern:"^\(\s+success\s+\(\s+\(([^)]+)\)", string:auth_request);

if(isnull(item) || isnull(item[1]))
  exit(1, "Error parsing auth-request for SVN service on port " + port + ".");

bad_mechs = make_list();

mechs = item[1];
if(" PLAIN " >< mechs) bad_mechs = make_list(bad_mechs, "PLAIN");
if(" LOGIN " >< mechs) bad_mechs = make_list(bad_mechs, "LOGIN");

if(max_index(bad_mechs) > 0)
{
  pci_report = 'The remote Subversion service on port ' + port + ' accepts cleartext logins.';
  set_kb_item(name:"PCI/ClearTextCreds/" + port, value:pci_report);

  report = '\n  Server supported SASL mechanisms : ' + mechs +
           '\n  Cleartext mechanisms supported   : ' + join(bad_mechs, sep:" ") + '\n';
  security_warning(port:port, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "SVN", port); 
