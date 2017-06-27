#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71783);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/07 20:46:53 $");

  script_cve_id("CVE-2013-5211");
  script_bugtraq_id(64692);
  script_osvdb_id(101576);
  script_xref(name:"CERT", value:"348126");
  script_xref(name:"EDB-ID", value:"33073");
  script_xref(name:"ICSA", value:"14-051-04");

  script_name(english:"Network Time Protocol Daemon (ntpd) monlist Command Enabled DoS");
  script_summary(english:"Checks if the remote ntpd supports the monlist command.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NTP server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ntpd running on the remote host has the 'monlist'
command enabled. This command returns a list of recent hosts that have
connected to the service. However, it is affected by a denial of
service vulnerability in ntp_request.c that allows an unauthenticated,
remote attacker to saturate network traffic to a specific IP address
by using forged REQ_MON_GETLIST or REQ_MON_GETLIST_1 requests.
Furthermore, an attacker can exploit this issue to conduct
reconnaissance or distributed denial of service (DDoS) attacks.");
  script_set_attribute(attribute:"see_also", value:"https://isc.sans.edu/diary/NTP+reflection+attack/17300");
  script_set_attribute(attribute:"see_also", value:"http://bugs.ntp.org/show_bug.cgi?id=1532");
  script_set_attribute(attribute:"see_also", value:"http://kb.juniper.net/InfoCenter/index?page=content&id=JSA10613");
  script_set_attribute(attribute:"solution", value:
"If using NTP from the Network Time Protocol Project, upgrade to
NTP version 4.2.7-p26 or later. Alternatively, add 'disable monitor'
to the ntp.conf configuration file and restart the service. Otherwise,
limit access to the affected service to trusted hosts, or contact the
vendor for a fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ntp_open.nasl");
  script_require_keys("NTP/Running");

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

# Make sure NTP server is running
get_kb_item_or_exit('NTP/Running');

port = get_service(svc:"ntp", ipproto:"udp", default:123, exit_on_fail:TRUE);

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");

req = raw_string(0x17, 0, 0x03, 0x2a, 0, 0, 0, 0);
req += mkpad(40);
send(socket:soc, data:req);
res = recv(socket:soc, length:508);
close(soc);

if (isnull(res)) audit(AUDIT_RESP_NOT, port, "an NTP 'monlist' command", "UDP");

if (strlen(res) < 8) audit(AUDIT_RESP_BAD, port, "an NTP 'monlist' command", "UDP");

impl = ord(res[2]);
code = ord(res[3]);

count = getword(blob:res, pos:4);
size = getword(blob:res, pos:6);

if (size == 0) audit(AUDIT_LISTEN_NOT_VULN, "NTP", port+" UDP");

if ((impl != 2 && impl != 3) || code != 42 || size != 72) audit(AUDIT_RESP_BAD, port, "an NTP 'monlist' command", "UDP");


if (report_verbosity > 0)
{
  off = 8;
  ips = "";

  for (i = 0; i < count; i++)
  {
    src = ord(res[off+16]) + "." + ord(res[off+17]) + "." + ord(res[off+18]) + "." + ord(res[off+19]);
    ips += src + '\n';
    off += size;
  }

  report = '\n' + 'Nessus was able to retrieve the following list of recent hosts to' +
           '\n' + 'connect to this NTP server :' +
           '\n' +
           '\n' + ips;
  security_warning(port:port, protocol:"udp", extra:report);
}
else security_warning(port:port, protocol:"udp");
