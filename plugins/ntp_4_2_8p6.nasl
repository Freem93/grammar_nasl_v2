#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88054);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/20 22:55:16 $");

  script_cve_id(
    "CVE-2015-7973",
    "CVE-2015-7974",
    "CVE-2015-7975",
    "CVE-2015-7976",
    "CVE-2015-7977",
    "CVE-2015-7978",
    "CVE-2015-7979",
    "CVE-2015-8138",
    "CVE-2015-8139",
    "CVE-2015-8140",
    "CVE-2015-8158"
  );
  script_bugtraq_id(
    81963,
    81811,
    81814,
    81815,
    81816,
    81959,
    81960,
    81962,
    82102,
    82105
  );
  script_osvdb_id(
    133378,
    133382,
    133383,
    133384,
    133385,
    133386,
    133387,
    133388,
    133389,
    133390,
    133391,
    133414
  );
  script_xref(name:"CERT", value:"718152");

  script_name(english:"Network Time Protocol Daemon (ntpd) 3.x / 4.x < 4.2.8p6 Multiple Vulnerabilities");
  script_summary(english:"Checks for a vulnerable NTP server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NTP server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the remote NTP server is 3.x or 4.x prior to 4.2.8p6.
It is, therefore, affected by the following vulnerabilities :

  - A flaw exists in the receive() function due to the use
    of authenticated broadcast mode. A man-in-the-middle
    attacker can exploit this to conduct a replay attack.
    (CVE-2015-7973)

  - A time serving flaw exists in the trusted key system
    due to improper key checks. An authenticated, remote
    attacker can exploit this to perform impersonation
    attacks between authenticated peers. (CVE-2015-7974)

  - An overflow condition exists in the nextvar() function
    due to improper validation of user-supplied input. A
    local attacker can exploit this to cause a buffer
    overflow, resulting in a denial of service condition.
    (CVE-2015-7975)

  - A flaw exists in ntp_control.c due to improper filtering
    of special characters in filenames by the saveconfig
    command. An authenticated, remote attacker can exploit
    this to inject arbitrary content. (CVE-2015-7976)

  - A NULL pointer dereference flaw exists in ntp_request.c
    that is triggered when handling ntpdc relist commands.
    A remote attacker can exploit this, via a specially
    crafted request, to crash the service, resulting in a
    denial of service condition. (CVE-2015-7977)

  - A flaw exists in ntpdc that is triggered during the
    handling of the relist command. A remote attacker can
    exploit this, via recursive traversals of the
    restriction list, to exhaust available space on the call
    stack, resulting in a denial of service condition.
    CVE-2015-7978)

  - An unspecified flaw exists in authenticated broadcast
    mode. A remote attacker can exploit this, via specially
    crafted packets, to cause a denial of service condition.
    (CVE-2015-7979)

  - A flaw exists in the receive() function that allows
    packets with an origin timestamp of zero to bypass
    security checks. A remote attacker can exploit this to
    spoof arbitrary content. (CVE-2015-8138)

  - A flaw exists in ntpq and ntpdc that allows a remote
    attacker to disclose sensitive information in
    timestamps. (CVE-2015-8139)

  - A flaw exists in the ntpq protocol that is triggered
    during the handling of an improper sequence of numbers.
    A man-in-the-middle attacker can exploit this to conduct
    a replay attack. (CVE-2015-8140)

  - A flaw exists in the ntpq client that is triggered when
    handling packets that cause a loop in the getresponse()
    function. A remote attacker can exploit this to cause an
    infinite loop, resulting in a denial of service
    condition. (CVE-2015-8158)");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/SecurityNotice");
  # http://support.ntp.org/bin/view/Main/SecurityNotice#January_2016_NTP_4_2_8p6_Securit
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d42322ca");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NTP version 4.2.8p6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/21");

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
if (!port) port = 123;

version = get_kb_item_or_exit("Services/ntp/version");
if (version == 'unknown') audit(AUDIT_UNKNOWN_APP_VER, app_name);

match = eregmatch(string:version, pattern:"([0-9a-z.]+)");
if (isnull(match) || empty_or_null(match[1])) exit(AUDIT_UNKNOWN_APP_VER, app_name);

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

# This vulnerability affects NTP 3.x / 4.x < 4.2.8p6
if (
  (major == 3) ||
  (major == 4 && minor < 2) ||
  (major == 4 && minor == 2 && rev < 8) ||
  (major == 4 && minor == 2 && rev == 8 && patch < 6)
)
{
  fix = "4.2.8p6";
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
