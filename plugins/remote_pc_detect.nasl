#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11673);
 script_version ("$Revision: 1.22 $");
 script_cvs_date("$Date: 2016/01/05 18:44:51 $");

 script_name(english: "Remote PC Access Server detection.");
 script_summary(english:"Checks for PC Anywhere.");

 script_set_attribute(attribute:"synopsis", value:
"PC Access Server is running on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Remote PC Access Server. It is, therefore,
affected by an information disclosure vulnerability due to the
protocol transmitting username and passwords in cleartext. A
man-in-the-middle attacker can exploit this to disclose the
credentials and then take control of the remote system.");
 script_set_attribute(attribute:"solution", value:
"Disable this service if you do not use it." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/29");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "Service detection");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencie("os_fingerprint.nasl", "find_service2.nasl");
 script_require_ports("Services/unknown", 34012);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

os = get_kb_item("Host/OS");
if(os)
 if("Windows" >!< os) audit(AUDIT_OS_NOT, "Windows", os);

answer = raw_string (0x99, 0xF3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF);

function probe(port)
{
  local_var r, soc, pci_report;

  if(get_port_state(port) == 0 ) audit(AUDIT_PORT_CLOSED, port);
  soc = open_sock_tcp(port);
  if(!soc) audit(AUDIT_SOCK_FAIL, port);

  send(socket:soc, data:raw_string(0x28, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00));
  r = recv(socket:soc, length:12);
  close(soc);

  if(strlen(r) == 12 && (answer >< r)) 
  {
    pci_report = 'The remote PC Access service on port ' + port + ' accepts cleartext logins.';
    set_kb_item(name:"PCI/ClearTextCreds/" + port, value:pci_report);
    security_warning(port);
    register_service(proto:"remote_pc", port:port);
    exit(0);
  }
}

if ( thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  )
	ports = add_port_in_list(list:get_kb_list("Services/unknown"), port:34012);
else
	ports = make_list(34012);

ports = list_uniq(ports);

port = branch(ports);

if (!service_is_unknown(port:port)) audit(AUDIT_SVC_ALREADY_KNOWN, port);

if( port == 135 || port == 139 || port == 445 )
  exit(0, "This plugin will not run against potential SMB port " + port + ".");

probe(port:port);

audit(AUDIT_NOT_DETECT, "PC Access Service", port);

