#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1177-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(90821);
  script_version("$Revision: 2.12 $");
  script_cvs_date("$Date: 2017/03/08 15:07:20 $");

  script_cve_id("CVE-2015-5300", "CVE-2015-7973", "CVE-2015-7974", "CVE-2015-7975", "CVE-2015-7976", "CVE-2015-7977", "CVE-2015-7978", "CVE-2015-7979", "CVE-2015-8138", "CVE-2015-8139", "CVE-2015-8140", "CVE-2015-8158");
  script_osvdb_id(129315, 133378, 133382, 133383, 133384, 133385, 133386, 133387, 133388, 133389, 133390, 133391, 133414);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : ntp (SUSE-SU-2016:1177-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ntp was updated to version 4.2.8p6 to fix 12 security issues.

Also yast2-ntp-client was updated to match some sntp syntax changes.
(bsc#937837)

These security issues were fixed :

  - CVE-2015-8158: Fixed potential infinite loop in ntpq
    (bsc#962966).

  - CVE-2015-8138: Zero Origin Timestamp Bypass
    (bsc#963002).

  - CVE-2015-7979: Off-path Denial of Service (DoS) attack
    on authenticated broadcast mode (bsc#962784).

  - CVE-2015-7978: Stack exhaustion in recursive traversal
    of restriction list (bsc#963000).

  - CVE-2015-7977: reslist NULL pointer dereference
    (bsc#962970).

  - CVE-2015-7976: ntpq saveconfig command allows dangerous
    characters in filenames (bsc#962802).

  - CVE-2015-7975: nextvar() missing length check
    (bsc#962988).

  - CVE-2015-7974: Skeleton Key: Missing key check allows
    impersonation between authenticated peers (bsc#962960).

  - CVE-2015-7973: Replay attack on authenticated broadcast
    mode (bsc#962995).

  - CVE-2015-8140: ntpq vulnerable to replay attacks
    (bsc#962994).

  - CVE-2015-8139: Origin Leak: ntpq and ntpdc, disclose
    origin (bsc#962997).

  - CVE-2015-5300: MITM attacker could have forced ntpd to
    make a step larger than the panic threshold
    (bsc#951629).

These non-security issues were fixed :

  - fate#320758 bsc#975981: Enable compile-time support for
    MS-SNTP (--enable-ntp-signd). This replaces the w32
    patches in 4.2.4 that added the authreg directive.

  - bsc#962318: Call /usr/sbin/sntp with full path to
    synchronize in start-ntpd. When run as cron job,
    /usr/sbin/ is not in the path, which caused the
    synchronization to fail.

  - bsc#782060: Speedup ntpq.

  - bsc#916617: Add /var/db/ntp-kod.

  - bsc#956773: Add ntp-ENOBUFS.patch to limit a warning
    that might happen quite a lot on loaded systems.

  - bsc#951559,bsc#975496: Fix the TZ offset output of sntp
    during DST.

  - Add ntp-fork.patch and build with threads disabled to
    allow name resolution even when running chrooted.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/782060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/916617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951559"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5300.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7973.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7974.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7975.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7976.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7977.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7978.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7979.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8138.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8139.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8140.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8158.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161177-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?62660ba3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1 :

zypper in -t patch SUSE-SLE-SDK-12-SP1-2016-694=1

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2016-694=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2016-694=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ntp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/02");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"ntp-4.2.8p6-8.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"ntp-debuginfo-4.2.8p6-8.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"ntp-debugsource-4.2.8p6-8.2")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"ntp-doc-4.2.8p6-8.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"ntp-4.2.8p6-8.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"ntp-debuginfo-4.2.8p6-8.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"ntp-debugsource-4.2.8p6-8.2")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"ntp-doc-4.2.8p6-8.2")) flag++;


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
