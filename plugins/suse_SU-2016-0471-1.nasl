#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0471-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(88832);
  script_version("$Revision: 2.21 $");
  script_cvs_date("$Date: 2017/01/27 23:31:26 $");

  script_cve_id("CVE-2014-9761", "CVE-2015-7547", "CVE-2015-8776", "CVE-2015-8777", "CVE-2015-8778", "CVE-2015-8779");
  script_osvdb_id(133568, 133572, 133574, 133577, 133580, 134584);
  script_xref(name:"TRA", value:"TRA-2017-08");
  script_xref(name:"IAVA", value:"2016-A-0053");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : glibc (SUSE-SU-2016:0471-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for glibc fixes the following security issues :

  - CVE-2015-7547: A stack-based buffer overflow in
    getaddrinfo allowed remote attackers to cause a crash or
    execute arbitrary code via crafted and timed DNS
    responses (bsc#961721)

  - CVE-2015-8777: Insufficient checking of LD_POINTER_GUARD
    environment variable allowed local attackers to bypass
    the pointer guarding protection of the dynamic loader on
    set-user-ID and set-group-ID programs (bsc#950944)

  - CVE-2015-8776: Out-of-range time values passed to the
    strftime function may cause it to crash, leading to a
    denial of service, or potentially disclosure information
    (bsc#962736)

  - CVE-2015-8778: Integer overflow in hcreate and hcreate_r
    could have caused an out-of-bound memory access. leading
    to application crashes or, potentially, arbitrary code
    execution (bsc#962737)

  - CVE-2014-9761: A stack overflow (unbounded alloca) could
    have caused applications which process long strings with
    the nan function to crash or, potentially, execute
    arbitrary code. (bsc#962738)

  - CVE-2015-8779: A stack overflow (unbounded alloca) in
    the catopen function could have caused applications
    which pass long strings to the catopen function to crash
    or, potentially execute arbitrary code. (bsc#962739)

The following non-security bugs were fixed :

  - bsc#955647: Resource leak in resolver

  - bsc#956716: Don't do lock elision on an error checking
    mutex

  - bsc#958315: Reinitialize dl_load_write_lock on fork

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956716"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962736"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962737"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9761.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7547.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8776.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8777.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8778.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8779.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160471-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b42a0ff"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2017-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1 :

zypper in -t patch SUSE-SLE-SDK-12-SP1-2016-271=1

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2016-271=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2016-271=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/18");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-2.19-35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-debuginfo-2.19-35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-debugsource-2.19-35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-devel-2.19-35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-devel-debuginfo-2.19-35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-locale-2.19-35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-locale-debuginfo-2.19-35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-profile-2.19-35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"nscd-2.19-35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"nscd-debuginfo-2.19-35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-32bit-2.19-35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-debuginfo-32bit-2.19-35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-devel-32bit-2.19-35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-devel-debuginfo-32bit-2.19-35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-locale-32bit-2.19-35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-locale-debuginfo-32bit-2.19-35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"glibc-profile-32bit-2.19-35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"glibc-2.19-35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"glibc-32bit-2.19-35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"glibc-debuginfo-2.19-35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"glibc-debuginfo-32bit-2.19-35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"glibc-debugsource-2.19-35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"glibc-devel-2.19-35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"glibc-devel-32bit-2.19-35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"glibc-devel-debuginfo-2.19-35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"glibc-devel-debuginfo-32bit-2.19-35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"glibc-locale-2.19-35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"glibc-locale-32bit-2.19-35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"glibc-locale-debuginfo-2.19-35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"glibc-locale-debuginfo-32bit-2.19-35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"nscd-2.19-35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"nscd-debuginfo-2.19-35.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
