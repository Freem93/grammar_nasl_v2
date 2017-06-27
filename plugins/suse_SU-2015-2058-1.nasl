#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:2058-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(87010);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2017/02/21 14:37:42 $");

  script_cve_id("CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702", "CVE-2015-7703", "CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7848", "CVE-2015-7849", "CVE-2015-7850", "CVE-2015-7851", "CVE-2015-7852", "CVE-2015-7853", "CVE-2015-7854", "CVE-2015-7855", "CVE-2015-7871");
  script_osvdb_id(116071, 126666, 129298, 129299, 129300, 129301, 129302, 129303, 129304, 129305, 129306, 129307, 129308, 129309, 129310, 129311);
  script_xref(name:"TRA", value:"TRA-2015-04");

  script_name(english:"SUSE SLED11 / SLES11 Security Update : ntp (SUSE-SU-2015:2058-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This ntp update provides the following security and non security 
fixes :

  - Update to 4.2.8p4 to fix several security issues
    (bsc#951608) :

  - CVE-2015-7871: NAK to the Future: Symmetric association
    authentication bypass via crypto-NAK

  - CVE-2015-7855: decodenetnum() will ASSERT botch instead
    of returning FAIL on some bogus values

  - CVE-2015-7854: Password Length Memory Corruption
    Vulnerability

  - CVE-2015-7853: Invalid length data provided by a custom
    refclock driver could cause a buffer overflow

  - CVE-2015-7852 ntpq atoascii() Memory Corruption
    Vulnerability

  - CVE-2015-7851 saveconfig Directory Traversal
    Vulnerability

  - CVE-2015-7850 remote config logfile-keyfile

  - CVE-2015-7849 trusted key use-after-free

  - CVE-2015-7848 mode 7 loop counter underrun

  - CVE-2015-7701 Slow memory leak in CRYPTO_ASSOC

  - CVE-2015-7703 configuration directives 'pidfile' and
    'driftfile' should only be allowed locally

  - CVE-2015-7704, CVE-2015-7705 Clients that receive a KoD
    should validate the origin timestamp field

  - CVE-2015-7691, CVE-2015-7692, CVE-2015-7702 Incomplete
    autokey data packet length checks

  - Use ntpq instead of deprecated ntpdc in start-ntpd
    (bnc#936327).

  - Add a controlkey to ntp.conf to make the above work.

  - Improve runtime configuration :

  - Read keytype from ntp.conf

  - Don't write ntp keys to syslog.

  - Don't let 'keysdir' lines in ntp.conf trigger the 'keys'
    parser.

  - Fix the comment regarding addserver in ntp.conf
    (bnc#910063).

  - Remove ntp.1.gz, it wasn't installed anymore.

  - Remove ntp-4.2.7-rh-manpages.tar.gz and only keep
    ntptime.8.gz. The rest is partially irrelevant,
    partially redundant and potentially outdated
    (bsc#942587).

  - Remove 'kod' from the restrict line in ntp.conf
    (bsc#944300).

  - Use SHA1 instead of MD5 for symmetric keys (bsc#905885).

  - Require perl-Socket6 (bsc#942441).

  - Fix incomplete backporting of 'rcntp ntptimemset'.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/905885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/910063"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7691.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7692.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7701.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7702.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7703.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7704.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7705.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7848.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7849.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7850.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7851.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7852.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7853.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7854.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7855.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7871.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20152058-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9441511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2015-04"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-ntp-12218=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-ntp-12218=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-ntp-12218=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"ntp-4.2.8p4-5.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"ntp-doc-4.2.8p4-5.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"ntp-4.2.8p4-5.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"ntp-doc-4.2.8p4-5.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"ntp-4.2.8p4-5.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"ntp-doc-4.2.8p4-5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp");
}
