#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(43156);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2009-3563");
  script_bugtraq_id(37255);
  script_osvdb_id(60847);
  script_xref(name:"CERT", value:"568372");
  script_xref(name:"Secunia", value:"37629");

  script_name(english:"NTP ntpd Mode 7 Error Response Packet Loop Remote DoS");
  script_summary(english:"Checks if the remote ntpd response to mode 7 error response");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote network time service has a denial of service
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of ntpd running on the remote host has a denial of
service vulnerability.  It responds to mode 7 error packets with its
own mode 7 error packets.  A remote attacker could exploit this by
sending a mode 7 error response with a spoofed IP header, setting the
source and destination IP addresses to the IP address of the target. 
This would cause ntpd to respond to itself endlessly, consuming
excessive amounts of CPU, resulting in a denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.ntp.org/show_bug.cgi?id=1331"
  );
  # http://support.ntp.org/bin/view/Main/SecurityNotice#DoS_attack_from_certain_NTP_mode
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a07ed05"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to NTP 4.2.4p8 / 4.2.6 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/11/04"  # first discussed on NTP bug tracker
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/12/08"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/12/14"
  );
 script_cvs_date("$Date: 2016/05/11 13:40:21 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("ntp_open.nasl");
  script_require_keys("NTP/Running");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");


port = get_kb_item("Services/udp/ntp");
if (isnull(port)) port = 123;

if (!get_udp_port_state(port))
  exit(0, 'UDP port '+port+' is not open.');

if ( islocalhost() ) exit(0, "This vulnerability can not be tested against localhost");

soc = open_sock_udp(port);
if (!soc) exit(1, "Failed to open socket to UDP port "+port+".");

req = raw_string(0x97, 0, 0, 0, 0x30, 0, 0, 0);
send(socket:soc, data:req);
res = recv(socket:soc, length:8);
close(soc);

if (isnull(res)) exit(1, "The NTP server on UDP port "+port+" didn't respond.");

# The service is vulnerable if it responds to a mode 7 error response with a
# mode 7 error response
if (res == req)
  security_warning(port:port, proto:"udp");
else
  exit(1, 'Unexpected response from NTP server on UDP port '+port+'.');
