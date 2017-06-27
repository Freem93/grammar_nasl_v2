#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0908-2.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(90303);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/04/05 21:32:30 $");

  script_cve_id("CVE-2015-5276");
  script_osvdb_id(127770);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : gcc5 (SUSE-SU-2016:0908-2)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The GNU Compiler Collection was updated to version 5.3.1, which brings
several fixes and enhancements.

The following security issue has been fixed :

  - Fix C++11 std::random_device short read issue that could
    lead to predictable randomness. (CVE-2015-5276,
    bsc#945842)

The following non-security issues have been fixed :

  - Enable frame pointer for TARGET_64BIT_MS_ABI when stack
    is misaligned. Fixes internal compiler error when
    building Wine. (bsc#966220)

  - Fix a PowerPC specific issue in gcc-go that broke
    compilation of newer versions of Docker. (bsc#964468)

  - Fix HTM built-ins on PowerPC. (bsc#955382)

  - Fix libgo certificate lookup. (bsc#953831)

  - Suppress deprecated-declarations warnings for inline
    definitions of deprecated virtual methods. (bsc#939460)

  - Revert accidental libffi ABI breakage on aarch64.
    (bsc#968771)

  - On x86_64, set default 32bit code generation to
    -march=x86-64 rather than -march=i586.

  - Add experimental File System TS library.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5276.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160908-2.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?853c2f17"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-gcc5-12484=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-gcc5-12484=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-gcc5-12484=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-gcc5-12484=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libatomic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libffi4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcc_s1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgfortran3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgomp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libquadmath0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-locale");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libatomic1-32bit-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libatomic1-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libffi4-32bit-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libffi4-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libgcc_s1-32bit-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libgfortran3-32bit-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libgomp1-32bit-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libstdc++6-32bit-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libquadmath0-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libquadmath0-32bit-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libatomic1-32bit-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libatomic1-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libffi4-32bit-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libffi4-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libgcc_s1-32bit-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libgfortran3-32bit-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libgomp1-32bit-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libstdc++6-32bit-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libgcc_s1-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libgfortran3-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libgomp1-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libstdc++6-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libstdc++6-locale-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"i586", reference:"libquadmath0-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libgcc_s1-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libgfortran3-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libgomp1-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libquadmath0-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libstdc++6-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libstdc++6-locale-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libgcc_s1-32bit-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libgfortran3-32bit-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libgomp1-32bit-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libquadmath0-32bit-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"libstdc++6-32bit-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libgcc_s1-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libgfortran3-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libgomp1-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libquadmath0-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libstdc++6-5.3.1+r233831-10.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"libstdc++6-locale-5.3.1+r233831-10.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gcc5");
}
