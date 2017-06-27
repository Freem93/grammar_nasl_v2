#
# (C) Tenable Network Security, Inc.
#

# there is already a nice WinMX check by Nessus...however, it relies on registry read access...this check
# works even without registry access...the anomaly is that when you connect to a WinMX client on port 6699
# immediatly after the handshake, the client send a PSH packet with a single byte of data set to "1"

include( 'compat.inc' );

if(description)
{
  script_id(11847);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_name(english:"WinMX Detection (uncredentialed check)");
  script_summary(english:"Determines if the remote system is running WinMX");

  script_set_attribute(
    attribute:'synopsis',
    value:'WinMX is a peer-to-peer file sharing application.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote server seems to be a WinMX Peer-to-Peer client,
which may not be suitable for a business environment. "
  );

  script_set_attribute(
    attribute:'solution',
    value: "Uninstall this software."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.ca.com/us/securityadvisor/pest/pest.aspx?id=453073289'
  );


 script_set_attribute(attribute:"plugin_publication_date", value: "2003/09/22");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english:"Peer-To-Peer File Sharing");
  script_require_ports(6699);
  exit(0);
}

#

port = 6699;
if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
r = recv(socket:soc, min:1, length:256);
if ( strlen(r) == 1 && r == "1" ) security_warning(port);
exit(0);
