#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90923);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/07 20:46:53 $");

  script_cve_id(
    "CVE-2015-7704",
    "CVE-2015-8138",
    "CVE-2016-1547",
    "CVE-2016-1548",
    "CVE-2016-1549",
    "CVE-2016-1550",
    "CVE-2016-1551",
    "CVE-2016-2516",
    "CVE-2016-2517",
    "CVE-2016-2518",
    "CVE-2016-2519"
  );
  script_bugtraq_id(
    88180,
    88189,
    88200,
    88204,
    88219,
    88226,
    88261,
    88264,
    88276
  );
  script_osvdb_id(
    129309,
    133383,
    137711,
    137712,
    137713,
    137714,
    137731,
    137732,
    137733,
    137734,
    137735
  );
  script_xref(name:"CERT", value:"718152");

  script_name(english:"Network Time Protocol Daemon (ntpd) 3.x / 4.x < 4.2.8p7 Multiple Vulnerabilities");
  script_summary(english:"Checks for a vulnerable NTP server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NTP server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the remote NTP server is 3.x or 4.x prior to 4.2.8p7.
It is, therefore, affected by the following vulnerabilities :

  - A denial of service vulnerability exists due to improper
    validation of the origin timestamp field when handling a
    Kiss-of-Death (KoD) packet. An unauthenticated, remote
    attacker can exploit this to cause a client to stop
    querying its servers, preventing the client from
    updating its clock. (CVE-2015-7704)

  - A flaw exists in the receive() function in ntp_proto.c
    that allows packets with an origin timestamp of zero to
    bypass security checks. An unauthenticated, remote
    attacker can exploit this to spoof arbitrary content.
    (CVE-2015-8138)

  - A denial of service vulnerability exists due to improper
    handling of a crafted Crypto NAK Packet with a source
    address spoofed to match that of an existing associated
    peer. An unauthenticated, remote attacker can exploit
    this to demobilize a client association. (CVE-2016-1547)

  - A denial of service vulnerability exists due to improper
    handling of packets spoofed to appear to be from a valid
    ntpd server. An unauthenticated, remote attacker can
    exploit this to cause NTP to switch from basic
    client/server mode to interleaved symmetric mode,
    causing the client to reject future legitimate
    responses. (CVE-2016-1548)

  - A race condition exists that is triggered during the
    handling of a saturation of ephemeral associations. An
    authenticated, remote attacker can exploit this to
    defeat NTP's clock selection algorithm and modify a
    user's clock. (CVE-2016-1549)

  - An information disclosure vulnerability exists in the
    message authentication functionality in libntp that is
    triggered during the handling of a series of specially
    crafted messages. An adjacent attacker can exploit this
    to partially recover the message digest key.
    (CVE-2016-1550)

  - A flaw exists due to improper filtering of IPv4 'bogon'
    packets received from a network. An unauthenticated,
    remote attacker can exploit this to spoof packets to
    appear to come from a specific reference clock.
    (CVE-2016-1551)

  - A denial of service vulnerability exists that allows an
    authenticated, remote attacker that has knowledge of the
    controlkey for ntpq or the requestkey for ntpdc to
    create a session with the same IP twice on an
    unconfigured directive line, causing ntpd to abort.
    (CVE-2016-2516)

  - A denial of service vulnerability exists that allows an
    authenticated, remote attacker to manipulate the value
    of the trustedkey, controlkey, or requestkey via a
    crafted packet, preventing authentication with ntpd
    until the daemon has been restarted. (CVE-2016-2517)

  - An out-of-bounds read error exists in the MATCH_ASSOC()
    function that occurs during the creation of peer
    associations with hmode greater than 7. An
    authenticated, remote attacker can exploit this, via a
    specially crafted packet, to cause a denial of service.
    (CVE-2016-2518)

  - An overflow condition exists in the ctl_getitem()
    function in ntpd due to improper validation of
    user-supplied input when reporting return values. An
    authenticated, remote attacker can exploit this to cause
    ntpd to abort. (CVE-2016-2519)");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/SecurityNotice");
  # http://support.ntp.org/bin/view/Main/SecurityNotice#April_2016_NTP_4_2_8p7_Security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a6d1cf4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NTP version 4.2.8p7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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
if (!port) port = 123;

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

# This vulnerability affects NTP 3.x / 4.x < 4.2.8p7
if (
  (major == 3) ||
  (major == 4 && minor < 2) ||
  (major == 4 && minor == 2 && rev < 8) ||
  (major == 4 && minor == 2 && rev == 8 && patch < 7)
)
{
  fix = "4.2.8p7";
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
  severity : SECURITY_WARNING
);
exit(0);
