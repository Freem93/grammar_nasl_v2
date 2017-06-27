#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10275);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");
  script_cve_id("CVE-1999-0637");

  script_name(english:"Systat Service Remote Information Disclosure");
  script_summary(english:"Checks for systat");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service inherently exposes potentially sensitive information.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The 'systat' service provides useful information
to an attacker, such as which processes are running, who is running them,
and so on. It is highly recommended that you disable this service."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Comment out the 'systat' line in /etc/inetd.conf"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.apps.ietf.org/rfc/rfc866.html'
  );


 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");
  script_dependencie("find_service1.nasl");
  script_require_ports("Services/systat", 11);
  exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/systat");
if(!port)port = 11;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  data = recv_line(socket:soc, length:1024);
  if("pid" >< tolower(data) )security_warning(port);
  close(soc);
 }
}
