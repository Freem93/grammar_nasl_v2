#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0963-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(90420);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/04/08 15:26:33 $");

  script_cve_id("CVE-2015-5276");
  script_osvdb_id(127770);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : gcc5 (SUSE-SU-2016:0963-1)");
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

  - Build s390[x] with '--with-tune=z9-109 --with-arch=z900'
    on SLE11 again. (bsc#954002)

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
    value:"https://bugzilla.suse.com/952151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954002"
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
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160963-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bca05937"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1 :

zypper in -t patch SUSE-SLE-SDK-12-SP1-2016-565=1

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2016-565=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2016-565=1

SUSE Linux Enterprise Module for Toolchain 12 :

zypper in -t patch SUSE-SLE-Module-Toolchain-12-2016-565=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2016-565=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2016-565=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libatomic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libatomic1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libatomic1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcilkrts5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcilkrts5-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcilkrts5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libffi-gcc5-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libffi4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libffi4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libffi4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcc_s1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcc_s1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcc_s1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgfortran3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgfortran3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgfortran3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgomp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgomp1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgomp1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libitm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libitm1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libitm1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liblsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liblsan0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmpx0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmpx0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmpx0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmpxwrappers0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmpxwrappers0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmpxwrappers0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libquadmath0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libquadmath0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libquadmath0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++6-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtsan0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libubsan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libubsan0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libubsan0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/08");
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
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libasan2-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libasan2-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libubsan0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libubsan0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libasan2-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libcilkrts5-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libcilkrts5-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libcilkrts5-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"liblsan0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"liblsan0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libmpx0-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libmpx0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libmpx0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libmpxwrappers0-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libmpxwrappers0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libmpxwrappers0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libquadmath0-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libquadmath0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libquadmath0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libtsan0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libtsan0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"libubsan0-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"gcc5-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"gcc5-debugsource-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libatomic1-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libatomic1-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libffi-gcc5-debugsource-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libffi4-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libffi4-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgcc_s1-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgcc_s1-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgfortran3-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgfortran3-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgomp1-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgomp1-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libitm1-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libitm1-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libstdc++6-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libstdc++6-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libstdc++6-locale-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libatomic1-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libffi4-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgcc_s1-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgfortran3-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libgomp1-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libitm1-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libstdc++6-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libasan2-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libasan2-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libubsan0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libubsan0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libasan2-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libasan2-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libcilkrts5-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libcilkrts5-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libcilkrts5-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libcilkrts5-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"liblsan0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"liblsan0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libmpx0-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libmpx0-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libmpx0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libmpx0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libmpxwrappers0-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libmpxwrappers0-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libmpxwrappers0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libmpxwrappers0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libquadmath0-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libquadmath0-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libquadmath0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libquadmath0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libtsan0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libtsan0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libubsan0-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libubsan0-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"gcc5-debugsource-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libatomic1-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libatomic1-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libffi-gcc5-debugsource-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libffi4-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libffi4-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgcc_s1-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgcc_s1-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgfortran3-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgfortran3-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgomp1-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgomp1-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libitm1-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libitm1-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libstdc++6-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libstdc++6-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libstdc++6-locale-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libatomic1-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libatomic1-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libffi4-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgcc_s1-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgcc_s1-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgfortran3-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgfortran3-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgomp1-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgomp1-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libitm1-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libitm1-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libstdc++6-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libstdc++6-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"gcc5-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"gcc5-debugsource-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libasan2-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libasan2-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libasan2-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libatomic1-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libatomic1-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libatomic1-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libcilkrts5-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libcilkrts5-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libcilkrts5-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libffi-gcc5-debugsource-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libffi4-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libffi4-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libffi4-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgcc_s1-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgcc_s1-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgcc_s1-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgfortran3-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgfortran3-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgfortran3-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgomp1-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgomp1-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libgomp1-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libitm1-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libitm1-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libitm1-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"liblsan0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"liblsan0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libmpx0-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libmpx0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libmpx0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libmpxwrappers0-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libmpxwrappers0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libmpxwrappers0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libquadmath0-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libquadmath0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libquadmath0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libstdc++6-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libstdc++6-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libstdc++6-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libstdc++6-locale-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtsan0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtsan0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libubsan0-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libubsan0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libubsan0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"gcc5-debugsource-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libasan2-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libasan2-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libasan2-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libasan2-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libatomic1-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libatomic1-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libatomic1-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libatomic1-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libcilkrts5-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libcilkrts5-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libcilkrts5-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libcilkrts5-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libffi-gcc5-debugsource-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libffi4-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libffi4-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libffi4-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libffi4-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgcc_s1-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgcc_s1-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgcc_s1-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgcc_s1-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgfortran3-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgfortran3-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgfortran3-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgfortran3-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgomp1-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgomp1-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgomp1-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgomp1-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libitm1-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libitm1-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libitm1-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libitm1-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"liblsan0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"liblsan0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmpx0-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmpx0-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmpx0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmpx0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmpxwrappers0-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmpxwrappers0-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmpxwrappers0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libmpxwrappers0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libquadmath0-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libquadmath0-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libquadmath0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libquadmath0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libstdc++6-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libstdc++6-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libstdc++6-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libstdc++6-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libstdc++6-locale-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libtsan0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libtsan0-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libubsan0-32bit-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libubsan0-32bit-debuginfo-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libubsan0-5.3.1+r233831-9.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libubsan0-debuginfo-5.3.1+r233831-9.1")) flag++;


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
