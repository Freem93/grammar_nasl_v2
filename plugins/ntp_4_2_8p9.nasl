#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95575);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/04/17 17:37:51 $");

  script_cve_id(
    "CVE-2016-7426",
    "CVE-2016-7427",
    "CVE-2016-7428",
    "CVE-2016-7429",
    "CVE-2016-7431",
    "CVE-2016-7433",
    "CVE-2016-7434",
    "CVE-2016-9310",
    "CVE-2016-9311",
    "CVE-2016-9312"
  );
  script_bugtraq_id(
    94444,
    94446,
    94447,
    94448,
    94450,
    94451,
    94452,
    94453,
    94454,
    94455
  );
  script_osvdb_id(
    147594,
    147595,
    147596,
    147597,
    147598,
    147599,
    147600,
    147601,
    147602,
    147603
  );
  script_xref(name:"CERT", value:"633847");

  script_name(english:"Network Time Protocol Daemon (ntpd) 4.x < 4.2.8p9 Multiple Vulnerabilities");
  script_summary(english:"Checks for a vulnerable NTP server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NTP server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the remote NTP server is 4.x prior to 4.2.8p9. It is,
therefore, affected by the following vulnerabilities :

  - A denial of service vulnerability exists when rate
    limiting is configured for all associations, the limits
    also being applied to responses received from the
    configured sources. An unauthenticated, remote attacker
    can exploit this, by periodically sending spoofed
    packets, to keep rate limiting active, resulting in
    valid responses not being accepted by ntpd from its
    sources. (CVE-2016-7426)

  - A denial of service vulnerability exists in the
    broadcast mode replay prevention functionality. An
    unauthenticated, adjacent attacker can exploit this, via
    specially crafted broadcast mode NTP packets
    periodically injected into the broadcast domain, to
    cause ntpd to reject broadcast mode packets from
    legitimate NTP broadcast servers. (CVE-2016-7427)

  - A denial of service vulnerability exists in the
    broadcast mode poll interval functionality. An
    unauthenticated, adjacent attacker can exploit this, via
    specially crafted broadcast mode NTP packets, to cause
    ntpd to reject packets from a legitimate NTP broadcast
    server. (CVE-2016-7428)

  - A denial of service vulnerability exists when receiving
    server responses on sockets that correspond to different
    interfaces than what were used in the request. An
    unauthenticated, remote attacker can exploit this, by
    sending repeated requests using specially crafted
    packets with spoofed source addresses, to cause ntpd
    to select the incorrect interface for the source, which
    prevents it from sending new requests until the
    interface list is refreshed. This eventually results in
    preventing ntpd from synchronizing with the source.
    (CVE-2016-7429)

  - A flaw exists that allows packets with an origin
    timestamp of zero to bypass security checks. An
    unauthenticated, remote attacker can exploit this to
    spoof arbitrary content. (CVE-2016-7431)

  - A flaw exists due to the root delay being included
    twice, which may result in the jitter value being higher
    than expected. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition.
    (CVE-2016-7433)

  - A denial of service vulnerability exists when handling
    specially crafted mrulist query packets that allows an
    unauthenticated, remote attacker to crash ntpd.
    (CVE-2016-7434)

  - A flaw exists in the control mode (mode 6) functionality
    when handling specially crafted control mode packets. An
    unauthenticated, adjacent attacker can exploit this to
    set or disable ntpd traps, resulting in the disclosure
    of potentially sensitive information, disabling of
    legitimate monitoring, or DDoS amplification.
    (CVE-2016-9310)

  - A NULL pointer dereference flaw exists in the
    report_event() function within file ntpd/ntp_control.c
    when the trap service handles certain peer events. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted packet, to cause a denial of service
    condition. (CVE-2016-9311)

  - A denial of service vulnerability exists when handling
    oversize UDP packets that allows an unauthenticated,
    remote attacker to crash ntpd. Note that this
    vulnerability only affects Windows versions.
    (CVE-2016-9312)");
  # http://support.ntp.org/bin/view/Main/SecurityNotice#November_2016_ntp_4_2_8p9_NTP_Se
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08645c8c");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3067");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3071");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3072");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3082");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3102");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3110");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3113");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3114");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3118");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3119");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NTP version 4.2.8p9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("ntp_open.nasl");
  script_require_keys("NTP/Running", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Make sure NTP server is running
get_kb_item_or_exit('NTP/Running');

app_name = "NTP Server";

port = get_kb_item("Services/udp/ntp");
if (empty_or_null(port)) port = 123;

version = get_kb_item_or_exit("Services/ntp/version");
if (version == 'unknown') audit(AUDIT_UNKNOWN_APP_VER, app_name);

match = eregmatch(string:version, pattern:"([0-9a-z.]+)");
if (isnull(match) || empty_or_null(match[1])) audit(AUDIT_UNKNOWN_APP_VER, app_name);

# Paranoia check
if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = match[1];
verfields = split(ver, sep:".", keep:FALSE);
major = int(verfields[0]);
minor = int(verfields[1]);
if ('p' >< verfields[2])
{
  revpatch = split(verfields[2], sep:"p", keep:FALSE);
  rev = int(revpatch[0]);
  patch = int(revpatch[1]);
}
else
{
  rev = verfields[2];
  patch = 0;
}

# This vulnerability affects NTP 4.x < 4.2.8p9
# Check for vuln, else audit out.
if (
  (major == 4 && minor < 2) ||
  (major == 4 && minor == 2 && rev < 8) ||
  (major == 4 && minor == 2 && rev == 8 && patch < 9)
)
{
  fix = "4.2.8p9";
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

report =
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix +
  '\n';

security_report_v4(
  port  : port,
  proto : "udp",
  extra : report,
  severity : SECURITY_HOLE
);
exit(0);
