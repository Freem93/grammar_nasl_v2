#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:1422-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83643);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/05/11 13:40:21 $");

  script_cve_id("CVE-2014-6457", "CVE-2014-6502", "CVE-2014-6504", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6513", "CVE-2014-6517", "CVE-2014-6519", "CVE-2014-6531", "CVE-2014-6558");
  script_bugtraq_id(70533, 70538, 70544, 70548, 70552, 70556, 70564, 70567, 70569, 70570, 70572);
  script_osvdb_id(99712, 113325, 113326, 113329, 113330, 113331, 113332, 113333, 113336, 113337, 113338);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : java-1_7_0-openjdk (SUSE-SU-2014:1422-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenJDK was updated to icedtea 2.5.3 (OpenJDK 7u71) fixing security
issues and bugs.

  - Security :

  - S8015256: Better class accessibility

  - S8022783, CVE-2014-6504: Optimize C2 optimizations

  - S8035162: Service printing service

  - S8035781: Improve equality for annotations

  - S8036805: Correct linker method lookup.

  - S8036810: Correct linker field lookup

  - S8036936: Use local locales

  - S8037066, CVE-2014-6457: Secure transport layer

  - S8037846, CVE-2014-6558: Ensure streaming of input
    cipher streams

  - S8038364: Use certificate exceptions correctly

  - S8038899: Safer safepoints

  - S8038903: More native monitor monitoring

  - S8038908: Make Signature more robust

  - S8038913: Bolster XML support

  - S8039509, CVE-2014-6512: Wrap sockets more thoroughly

  - S8039533, CVE-2014-6517: Higher resolution resolvers

  - S8041540, CVE-2014-6511: Better use of pages in font
    processing

  - S8041529: Better parameterization of parameter lists

  - S8041545: Better validation of generated rasters

  - S8041564, CVE-2014-6506: Improved management of logger
    resources

  - S8041717, CVE-2014-6519: Issue with class file parser

  - S8042609, CVE-2014-6513: Limit splashiness of splash
    images

  - S8042797, CVE-2014-6502: Avoid strawberries in LogRecord

  - S8044274, CVE-2014-6531: Proper property processing

  - Backports :

  - S4963723: Implement SHA-224

  - S7044060: Need to support NSA Suite B Cryptography
    algorithms

  - S7122142: (ann) Race condition between
    isAnnotationPresent and getAnnotations

  - S7160837: DigestOutputStream does not turn off digest
    calculation when 'close()' is called

  - S8006935: Need to take care of long secret keys in
    HMAC/PRF computation

  - S8012637: Adjust CipherInputStream class to work in
    AEAD/GCM mode

  - S8028192: Use of PKCS11-NSS provider in FIPS mode broken

  - S8038000: java.awt.image.RasterFormatException:
    Incorrect scanline stride

  - S8039396: NPE when writing a class descriptor object to
    a custom ObjectOutputStream

  - S8042603: 'SafepointPollOffset' was not declared in
    static member function 'static bool
    Arguments::check_vm_args_consistency()'

  - S8042850: Extra unused entries in ICU ScriptCodes enum

  - S8052162: REGRESSION: sun/java2d/cmm/ColorConvertOp
    tests fail since 7u71 b01

  - S8053963: (dc) Use DatagramChannel.receive() instead of
    read() in connect()

  - S8055176: 7u71 l10n resource file translation update

  - Bugfixes :

  - PR1988: C++ Interpreter should no longer be used on
    ppc64

  - PR1989: Make jdk_generic_profile.sh handle missing
    programs better and be more verbose

  - PR1992, RH735336: Support retrieving proxy settings on
    GNOME 3.12.2

  - PR2000: Synchronise HEAD tarball paths with release
    branch paths

  - PR2002: Fix references to hotspot.map following PR2000

  - PR2003: --disable-system-gtk option broken by
    refactoring in PR1736

  - PR2009: Checksum of policy JAR files changes on every
    build

  - PR2014: Use version from hotspot.map to create tarball
    filename

  - PR2015: Update hotspot.map documentation in INSTALL

  - PR2025: LCMS_CFLAGS and LCMS_LIBS should not be used
    unless SYSTEM_LCMS is enabled

  - RH1015432: java-1.7.0-openjdk: Fails on PPC with
    StackOverflowError (revised comprehensive fix)

  - CACAO

  - PR2030, G453612, CA172: ARM hardfloat support for CACAO

  - AArch64 port

  - AArch64 C2 instruct for smull

  - Add frame anchor fences.

  - Add MacroAssembler::maybe_isb()

  - Add missing instruction synchronization barriers and
    cache flushes.

  - Add support for a few simple intrinsics

  - Add support for builtin crc32 instructions

  - Add support for Neon implementation of CRC32

  - All address constants are 48 bits in size.

  - array load must only read 32 bits

  - Define uabs(). Use it everywhere an absolute value is
    wanted.

  - Fast string comparison

  - Fast String.equals()

  - Fix register usage in generate_verify_oop().

  - Fix thinko in Atomic::xchg_ptr.

  - Fix typo in fsqrts

  - Improve C1 performance improvements in ic_cache checks

  - Performance improvement and ease of use changes pulled
    from upstream

  - Remove obsolete C1 patching code.

  - Replace hotspot jtreg test suite with tests from jdk7u

  - S8024648: 7141246 breaks Zero port

  - Save intermediate state before removing C1 patching
    code.

  - Unwind native AArch64 frames.

  - Use 2- and 3-instruction immediate form of movoop and
    mov_metadata in C2-generated code.

  - Various concurrency fixes.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6457.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6502.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6504.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6506.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6511.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6512.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6513.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6517.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6519.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6531.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-6558.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=901242"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20141422-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc412d22"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2014-68

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2014-68

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_7_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
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
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-1.7.0.71-6.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.71-6.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-debugsource-1.7.0.71-6.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-demo-1.7.0.71-6.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.71-6.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-devel-1.7.0.71-6.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.71-6.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-headless-1.7.0.71-6.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.71-6.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"java-1_7_0-openjdk-1.7.0.71-6.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.71-6.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"java-1_7_0-openjdk-debugsource-1.7.0.71-6.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-1.7.0.71-6.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.71-6.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_0-openjdk");
}
