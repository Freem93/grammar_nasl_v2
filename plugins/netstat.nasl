#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10157);
  script_version ("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");
  script_cve_id("CVE-1999-0650");
  script_osvdb_id(123);

  script_name(english:"Multiple Unix Netstat Service Remote Information Disclosure");
  script_summary(english:"Checks for netstat");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to an information disclosure flaw.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote host is running a 'netstat' service on this port.

The 'netstat' service provides useful information to an attacker, since
it gives away the state of the active connections. It is recommended that
you disable this service if you do not use it."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Disable the service by commenting out the 'netstat' line
in /etc/inetd.conf and restart the inetd process."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");


 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1990/01/01");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");
  script_dependencie("find_service1.nasl");
  script_require_ports("Services/netstat", 15);
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
port = get_kb_item("Services/netstat");
if(!port)port = 15;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  data = recv_line(socket:soc, length:1024);
  data_low = tolower(data);
  if("active " >< data_low || "established" >< data_low ||
     "time_wait" >< data_low || "close_wait" >< data_low)
  {
    security_warning(port);
    register_service(port: port, proto: "Services/netstat");
  }
  close(soc);
 }
}
