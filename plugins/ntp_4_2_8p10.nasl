#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97988);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/03/31 21:35:24 $");

  script_cve_id(
    "CVE-2016-9042",
    "CVE-2017-6451",
    "CVE-2017-6452",
    "CVE-2017-6455",
    "CVE-2017-6458",
    "CVE-2017-6459",
    "CVE-2017-6460",
    "CVE-2017-6462",
    "CVE-2017-6463",
    "CVE-2017-6464"
  );
  script_bugtraq_id(
    97045,
    97046,
    97049,
    97050,
    97051,
    97052,
    97058
  );
  script_osvdb_id(
    154200,
    154201,
    154202,
    154203,
    154204,
    154205,
    154206,
    154207,
    154208,
    154209,
    154210,
    154211,
    154212,
    154277,
    154458
  );
  script_xref(name:"CERT", value:"325339");
  script_xref(name:"IAVA", value:"2017-A-0084");

  script_name(english:"Network Time Protocol Daemon (ntpd) 4.x < 4.2.8p10 Multiple Vulnerabilities");
  script_summary(english:"Checks for a vulnerable NTP server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NTP server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the remote NTP server is 4.x prior to 4.2.8p10. It is,
therefore, affected by the following vulnerabilities :

  - A denial of service vulnerability exists in the
    receive() function within file ntpd/ntp_proto.c due to
    the expected origin timestamp being cleared when a
    packet with a zero origin timestamp is received. An
    unauthenticated, remote attacker can exploit this issue,
    via specially crafted network packets, to reset the
    expected origin timestamp for a target peer, resulting
    in legitimate replies being dropped. (CVE-2016-9042)

  - An out-of-bounds write error exists in the mx4200_send()
    function within file ntpd/refclock_mx4200.c due to
    improper handling of the return value of the snprintf()
    and vsnprintf() functions. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition or possibly the execution of arbitrary code.
    However, neither the researcher nor vendor could find
    any exploitable code path. (CVE-2017-6451)

  - A stack-based buffer overflow condition exists in the
    addSourceToRegistry() function within file
    ports/winnt/instsrv/instsrv.c due to improper validation
    of certain input when adding registry keys. A local
    attacker can exploit this to execute arbitrary code.
    (CVE-2017-6452)

  - A flaw exists due to dynamic link library (DLL) files
    being preloaded when they are defined in the inherited
    environment variable 'PPSAPI_DLLS'. A local attacker can
    exploit this, via specially crafted DLL files, to
    execute arbitrary code with elevated privileges.
    (CVE-2017-6455)

  - Multiple stack-based buffer overflow conditions exist in
    various wrappers around the ctl_putdata() function
    within file ntpd/ntp_control.c due to improper
    validation of certain input from the ntp.conf file.
    An unauthenticated, remote attacker can exploit these,
    by convincing a user into deploying a specially
    crafted ntp.conf file, to cause a denial of service
    condition or possibly the execution of arbitrary code.
    (CVE-2017-6458)

  - A flaw exists in the addKeysToRegistry() function within
    file ports/winnt/instsrv/instsrv.c when running the
    Windows installer due to improper termination of strings
    used for adding registry keys, which may cause malformed
    registry entries to be created. A local attacker can
    exploit this issue to possibly disclose sensitive memory
    contents. (CVE-2017-6459)

  - A stack-based buffer overflow condition exists in the
    reslist() function within file ntpq/ntpq-subs.c when
    handling server responses due to improper validation of
    certain input. An unauthenticated, remote attacker can
    exploit this, by convincing a user to connect to a
    malicious NTP server and by using a specially crafted
    server response, to cause a denial of service condition
    or the execution of arbitrary code. (CVE-2017-6460)

  - A stack-based buffer overflow condition exists in the
    datum_pts_receive() function within file
    ntpd/refclock_datum.c when handling handling packets
    from the '/dev/datum' device due to improper validation
    of certain input. A local attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2017-6462)

  - A denial of service vulnerability exists within file
    ntpd/ntp_config.c when handling 'unpeer' configuration
    options. An authenticated, remote attacker can exploit
    this issue, via an 'unpeer' option value of '0', to
    crash the ntpd daemon. (CVE-2017-6463)

  - A denial of service vulnerability exists when handling
    configuration directives. An authenticated, remote
    attacker can exploit this, via a malformed 'mode'
    configuration directive, to crash the ntpd daemon.
    (CVE-2017-6464)

  - A flaw exists in the ntpq_stripquotes() function within
    file ntpq/libntpq.c due to the function returning an
    incorrect value. An unauthenticated, remote attacker can
    possibly exploit this to have an unspecified impact.
    (VulnDB 154204)

  - An off-by-one overflow condition exists in the
    oncore_receive() function in file ntpd/refclock_oncore.c
    that possibly allows an unauthenticated, remote attacker
    to have an unspecified impact. (VulnDB 154208)

  - A flaw exists due to certain code locations not invoking
    the appropriate ereallocarray() and eallocarray()
    functions. An unauthenticated, remote attacker can
    possibly exploit this to have an unspecified impact.
    (VulnDB 154210)

  - A flaw exists due to the static inclusion of unused code
    from the libisc, libevent, and libopts libraries. An
    unauthenticated, remote attacker can possibly exploit
    this to have an unspecified impact. (VulnDB 154211)

  - A security weakness exists in the Makefile due to a
    failure to provide compile or link flags to offer
    hardened security options by default. (VulnDB 154458)");
  # http://support.ntp.org/bin/view/Main/SecurityNotice#March_2017_ntp_4_2_8p10_NTP_Secu
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68156231");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3361");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3376");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3377");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3378");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3379");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3380");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3381");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3382");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3383");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3384");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3385");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3386");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3387");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3388");
  script_set_attribute(attribute:"see_also", value:"http://support.ntp.org/bin/view/Main/NtpBug3389");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NTP version 4.2.8p10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

# This vulnerability affects NTP 4.x < 4.2.8p10
# Check for vuln, else audit out.
if (
  (major == 4 && minor < 2) ||
  (major == 4 && minor == 2 && rev < 8) ||
  (major == 4 && minor == 2 && rev == 8 && patch < 10)
)
{
  fix = "4.2.8p10";
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
