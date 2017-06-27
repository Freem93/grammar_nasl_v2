#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1844-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(86696);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/04/05 21:32:29 $");

  script_cve_id("CVE-2014-8121", "CVE-2015-1781");
  script_bugtraq_id(73038, 74255);
  script_osvdb_id(119253, 121105);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : glibc (SUSE-SU-2015:1844-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"glibc was updated to fix bugs and security issues.

Security issues fixed :

  - A buffer overflow in nss_dns was fixed that could lead
    to crashes. (CVE-2015-1781, bsc#927080, BZ #18287)

  - A denial of service attack (out of memory) in the NSS
    files backend was fixed (CVE-2014-8121, bsc#918187,
    GLIBC BZ #18007)

Non security bugs fixed :

  - Fix regression in threaded application malloc
    performance (bsc#915955, GLIBC#17195)

  - Fix read past end of pattern in fnmatch (bsc#920338,
    GLIBC#17062, GLIBC#18032, GLIBC#18036)

  - Record TTL also for DNS PTR queries (bsc#928723,
    GLIBC#18513)

  - Increase MINSIGSTKSZ and SIGSTKSZ for aarch64
    (bsc#931480, GLIBC#16850)

  - Fix handling of IPv6 nameservers (bsc#939211,
    GLIBC#13028, GLIBC#17053)

  - Avoid use of asm/ptrace.h (bsc#934084)

  - Do not corrupt the top of a threaded heap if top chunk
    is MINSIZE (GLIBC#18502)

  - Terminate unwinding after makecontext_ret on s390
    (bsc#940332. bsc#944494, GLIBC#18508)

  - Restore signal mask in set/swapcontext on s390
    (bsc#940195, bsc#944494, GLIBC#18080)

  - fix dlopen in static binaries (bsc#937853, GLIBC#17250)

  - Properly reread entry after failure in nss_files getent
    function (bsc#945779, BZ #18991)

Features added :

  - AVX512 support (fate#318844)

  - Add compatibility symlinks for LSB 3.0 (fate#318933)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/918187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/920338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8121.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1781.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151844-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?efda6e48"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-764=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-764=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-764=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-locale-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nscd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-debuginfo-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-debugsource-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-devel-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-devel-debuginfo-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-locale-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-locale-debuginfo-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-profile-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"nscd-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"nscd-debuginfo-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-32bit-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-debuginfo-32bit-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-devel-32bit-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-devel-debuginfo-32bit-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-locale-32bit-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-locale-debuginfo-32bit-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"glibc-profile-32bit-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-32bit-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-debuginfo-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-debuginfo-32bit-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-debugsource-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-devel-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-devel-32bit-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-devel-debuginfo-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-devel-debuginfo-32bit-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-locale-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-locale-32bit-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-locale-debuginfo-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"glibc-locale-debuginfo-32bit-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"nscd-2.19-22.7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"nscd-debuginfo-2.19-22.7.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
