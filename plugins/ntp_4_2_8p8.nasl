#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91515);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/07 20:46:53 $");

  script_cve_id(
    "CVE-2016-4953",
    "CVE-2016-4954",
    "CVE-2016-4955",
    "CVE-2016-4956",
    "CVE-2016-4957"
  );
  script_bugtraq_id(
    91010,
    91007,
    91009
  );
  script_osvdb_id(
    139280,
    139281,
    139282,
    139283,
    139284
  );
  script_xref(name:"CERT", value:"321640");

  script_name(english:"Network Time Protocol Daemon (ntpd) 4.x < 4.2.8p8 / 4.3.x < 4.3.93 Multiple Vulnerabilities");
  script_summary(english:"Checks for a vulnerable NTP server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NTP server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the remote NTP server is 4.x prior to 4.2.8p8 or 4.3.x
prior to 4.3.93. It is, therefore, affected by the following
vulnerabilities :
  
  - A denial of service vulnerability exists when handling
    authentication due to improper packet timestamp checks.
    An unauthenticated, remote attacker can exploit this,
    via a specially crafted and spoofed packet, to
    demobilize the ephemeral associations. (CVE-2016-4953)

  - A flaw exists that is triggered when handling spoofed
    packets. An unauthenticated, remote attacker can exploit
    this, via specially crafted packets, to affect peer
    variables (e.g., cause leap indications to be set). Note
    that the attacker must be able to spoof packets with
    correct origin timestamps from servers before expected
    response packets arrive. (CVE-2016-4954)

  - A flaw exists that is triggered when handling spoofed
    packets. An unauthenticated, remote attacker can exploit
    this, via specially crafted packets, to reset autokey
    associations. Note that the attacker must be able to
    spoof packets with correct origin timestamps from
    servers before expected response packets arrive.
    (CVE-2016-4955)

  - A flaw exists when handling broadcast associations that
    allows an unauthenticated, remote attacker to cause a
    broadcast client to change into interleave mode.
    (CVE-2016-4956)

  - A denial of service vulnerability exists when handling
    CRYPTO_NAK packets that allows an unauthenticated,
    remote attacker to cause a crash. Note that this issue
    only affects versions 4.2.8p7 and 4.3.92.
    (CVE-2016-4957)");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/SecurityNotice");
  # http://support.ntp.org/bin/view/Main/SecurityNotice#June_2016_ntp_4_2_8p8_NTP_Securi
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7bd9ab96");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3042");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3043");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3044");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3045");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3046");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NTP version 4.2.8p8 / 4.3.93 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/08");

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

# This vulnerability affects NTP 4.x < 4.2.8p8 / 4.3.x < 4.3.93
# Check for vuln, else audit out.
if (
  (major == 4 && minor < 2) ||
  (major == 4 && minor == 2 && rev < 8) ||
  (major == 4 && minor == 2 && rev == 8 && patch < 8)
)
{
  fix = "4.2.8p8";
}
else if (
  major == 4 && minor == 3 && rev < 93
){
  fix = "4.3.93";
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
