#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1568-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(91663);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2017/02/27 15:13:34 $");

  script_cve_id("CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7974", "CVE-2016-1547", "CVE-2016-1548", "CVE-2016-1549", "CVE-2016-1550", "CVE-2016-1551", "CVE-2016-2516", "CVE-2016-2517", "CVE-2016-2518", "CVE-2016-2519", "CVE-2016-4953", "CVE-2016-4954", "CVE-2016-4955", "CVE-2016-4956", "CVE-2016-4957");
  script_osvdb_id(129309, 129310, 133387, 137711, 137712, 137713, 137714, 137731, 137732, 137733, 137734, 137735, 139280, 139281, 139282, 139283, 139284);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : ntp (SUSE-SU-2016:1568-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ntp was updated to version 4.2.8p8 to fix 17 security issues.

These security issues were fixed :

  - CVE-2016-4956: Broadcast interleave (bsc#982068).

  - CVE-2016-2518: Crafted addpeer with hmode > 7 causes
    array wraparound with MATCH_ASSOC (bsc#977457).

  - CVE-2016-2519: ctl_getitem() return value not always
    checked (bsc#977458).

  - CVE-2016-4954: Processing spoofed server packets
    (bsc#982066).

  - CVE-2016-4955: Autokey association reset (bsc#982067).

  - CVE-2015-7974: NTP did not verify peer associations of
    symmetric keys when authenticating packets, which might
    allowed remote attackers to conduct impersonation
    attacks via an arbitrary trusted key, aka a 'skeleton
    key (bsc#962960).

  - CVE-2016-4957: CRYPTO_NAK crash (bsc#982064).

  - CVE-2016-2516: Duplicate IPs on unconfig directives will
    cause an assertion botch (bsc#977452).

  - CVE-2016-2517: Remote configuration
    trustedkey/requestkey values are not properly validated
    (bsc#977455).

  - CVE-2016-4953: Bad authentication demobilizes ephemeral
    associations (bsc#982065).

  - CVE-2016-1547: CRYPTO-NAK DoS (bsc#977459).

  - CVE-2016-1551: Refclock impersonation vulnerability,
    AKA: refclock-peering (bsc#977450).

  - CVE-2016-1550: Improve NTP security against buffer
    comparison timing attacks, authdecrypt-timing, AKA:
    authdecrypt-timing (bsc#977464).

  - CVE-2016-1548: Interleave-pivot - MITIGATION ONLY
    (bsc#977461).

  - CVE-2016-1549: Sybil vulnerability: ephemeral
    association attack, AKA: ntp-sybil - MITIGATION ONLY
    (bsc#977451).

This release also contained improved patches for CVE-2015-7704,
CVE-2015-7705, CVE-2015-7974.

These non-security issues were fixed :

  - bsc#979302: Change the process name of the forking DNS
    worker process to avoid the impression that ntpd is
    started twice.

  - bsc#981422: Don't ignore SIGCHILD because it breaks
    wait().

  - bsc#979981: ntp-wait does not accept fractional seconds,
    so use 1 instead of 0.2 in ntp-wait.service.

  - Separate the creation of ntp.keys and key #1 in it to
    avoid problems when upgrading installations that have
    the file, but no key #1, which is needed e.g. by 'rcntp
    addserver'.

  - bsc#957226: Restrict the parser in the startup script to
    the first occurrance of 'keys' and 'controlkey' in
    ntp.conf.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982068"
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
    value:"https://www.suse.com/security/cve/CVE-2015-7974.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1547.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1548.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1549.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1550.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1551.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2516.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2517.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2518.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2519.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4953.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4954.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4955.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4956.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4957.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161568-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57fb52ad"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2016-933=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2016-933=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ntp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"ntp-4.2.8p8-46.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"ntp-debuginfo-4.2.8p8-46.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"ntp-debugsource-4.2.8p8-46.8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"ntp-doc-4.2.8p8-46.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"ntp-4.2.8p8-46.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"ntp-debuginfo-4.2.8p8-46.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"ntp-debugsource-4.2.8p8-46.8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"ntp-doc-4.2.8p8-46.8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp");
}
