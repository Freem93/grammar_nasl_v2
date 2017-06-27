#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19517);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/07 20:46:53 $");

  script_cve_id("CVE-2005-2496");
  script_bugtraq_id(14673);
  script_osvdb_id(19055);

  script_name(english:"Network Time Protocol Daemon (ntpd) < 4.2.1 -u Group Permission Weakness Privilege Escalation");
  script_summary(english:"Checks for incorrect group privileges vulnerability in ntpd.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NTP server is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the NTP (Network Time Protocol)
server running on the remote host is affected by a flaw that causes it
to run with the permissions of a privileged user if a group name
rather than a group ID is specified on the command line. A local
attacker, who has managed to compromise the application through some
other means, can exploit this issue to gain elevated privileges.");
  script_set_attribute(attribute:"see_also", value:"http://bugs.ntp.org/show_bug.cgi?id=392");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NTP version 4.2.1 or later. Alternatively, start ntpd with
a group number.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencie("ntp_open.nasl");
  script_require_keys("NTP/Running", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");

# Make sure NTP server is running
get_kb_item_or_exit('NTP/Running');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = 123;
soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");


# Pull up the version number.
#
# nb: this replicates "echo rv | ntpq target".
pkt = raw_string(
  0x16, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
);
send(socket:soc, data:pkt);
res = recv(socket:soc, length:4096);
close(soc);

if (res) {
  ver = strstr(res, 'version="ntpd ');
  if (ver) ver = ver - 'version="ntpd ';
  if (ver) ver = ver - strstr(ver, " ");

  # The bug report says the flaw is fixed in 4.2.1.
  if (ver && ver =~ "^([0-3]\.|4\.([01]|2\.0))")
    security_warning(port:port, protocol:"udp");
  else
    audit(AUDIT_INST_VER_NOT_VULN, "NTP Server", ver);
}
else audit(AUDIT_RESP_NOT, port);
