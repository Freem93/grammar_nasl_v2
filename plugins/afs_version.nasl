#
# This script was written by Lionel Cons <lionel.cons@cern.ch>, CERN
#
# Changes by Tenable:
# - Changed plugin family (1/21/2009)


include("compat.inc");

if (description)
{
  script_id(10441);
  script_version ("$Revision: 1.17 $");
  script_name(english:"AFS Client Version Detection");
  script_summary(english:"Detects the AFS Client Version");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running the AFS client." );
 script_set_attribute(attribute:"description", value:
"This detects the AFS client version by connecting to the AFS callback
port and processing the buffer received. The client version gives
potential attackers additional information about the system they are
attacking. Versions and types should be ommited where possible." );
 script_set_attribute(attribute:"see_also", value:"http://www.openafs.org" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/06/14");
 script_cvs_date("$Date: 2011/03/11 21:52:30 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2000-2011 CERN");

  script_family(english:"Service detection");
  exit(0);
}

#
# script
#
port = 7001;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is closed.");
sock = open_sock_udp(port);
if (! sock) exit(1, "UDP connection failed to port "+port+".");

  data = raw_string(0x00, 0x00, 0x03, 0xe7, 0x00, 0x00, 0x00, 0x00,
	            0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x00,
	            0x00, 0x00, 0x00, 0x00, 0x0d, 0x05, 0x00, 0x00,
	            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  send(socket:sock, data:data);
  max = 80;
  info = recv(socket:sock, length:max);
  if (strlen(info) > 28) {
    data = "AFS version: ";
    for (i = 28; i < max; i = i + 1) {
      if (info[i] == raw_string(0x00)) {
        i = max;
      } else {
        data = data + info[i];
      }
    }
    security_note(port:port, protocol:"udp", extra:data);
  }
  close(sock);
