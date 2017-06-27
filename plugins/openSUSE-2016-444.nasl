#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-444.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(90481);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/24 13:46:11 $");

  script_cve_id("CVE-2016-0636");

  script_name(english:"openSUSE Security Update : java-1_7_0-openjdk (openSUSE-2016-444)");
  script_summary(english:"Check for the openSUSE-2016-444 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The OpenJDK Java java-1_7_0-openjdk was updated to 2.6.5 to fix the
following issues :

Update to 2.6.5 - OpenJDK 7u99 (bsc#972468)

  - Security fixes

  - S8152335, CVE-2016-0636: Improve MethodHandle
    consistency

  - Import of OpenJDK 7 u99 build 0

  - S6425769, PR2858: Allow specifying an address to bind
    JMX remote connector

  - S6961123: setWMClass fails to null-terminate WM_CLASS
    string

  - S8145982, PR2858: JMXInterfaceBindingTest is failing
    intermittently

  - S8146015, PR2858: JMXInterfaceBindingTest is failing
    intermittently for IPv6 addresses

  - Backports

  - S8028727, PR2814: [parfait] warnings from b116 for
    jdk.src.share.native.sun.security.ec: JNI pending
    exceptions

  - S8048512, PR2814: Uninitialised memory in
    jdk/src/share/native/sun/security/ec/ECC_JNI.cpp

  - S8071705. PR2819, RH1182694: Java application menu
    misbehaves when running multiple screen stacked
    vertically

  - S8150954, PR2866, RH1176206: AWT Robot not compatible
    with GNOME Shell

  - Bug fixes

  - PR2803: Make system CUPS optional

  - PR2886: Location of 'stap' executable is hard-coded

  - PR2893: test/tapset/jstaptest.pl should be executable

  - PR2894: Add missing test directory in make check.

  - CACAO

  - PR2781, CA195: typeinfo.cpp: typeinfo_merge_nonarrays:
    Assertion `dest && result && x.any && y.any' failed

  - AArch64 port

  - PR2852: Add support for large code cache

  - PR2852: Apply ReservedCodeCacheSize default limiting to
    AArch64 only.

  - S8081289, PR2852: aarch64: add support for
    RewriteFrequentPairs in interpreter

  - S8131483, PR2852: aarch64: illegal stlxr instructions

  - S8133352, PR2852: aarch64: generates constrained
    unpredictable instructions

  - S8133842, PR2852: aarch64: C2 generates illegal
    instructions with int shifts >=32

  - S8134322, PR2852: AArch64: Fix several errors in C2
    biased locking implementation

  - S8136615, PR2852: aarch64: elide DecodeN when followed
    by CmpP 0

  - S8138575, PR2852: Improve generated code for profile
    counters

  - S8138641, PR2852: Disable C2 peephole by default for
    aarch64

  - S8138966, PR2852: Intermittent SEGV running ParallelGC

  - S8143067, PR2852: aarch64: guarantee failure in javac

  - S8143285, PR2852: aarch64: Missing load acquire when
    checking if ConstantPoolCacheEntry is resolved

  - S8143584, PR2852: Load constant pool tag and class
    status with load acquire

  - S8144201, PR2852: aarch64:
    jdk/test/com/sun/net/httpserver/Test6a.java fails with

    --enable-unlimited-crypto

  - S8144582, PR2852: AArch64 does not generate correct
    branch profile data

  - S8146709, PR2852: AArch64: Incorrect use of ADRP for
    byte_map_base

  - S8147805, PR2852: aarch64: C1 segmentation fault due to
    inline Unsafe.getAndSetObject

  - S8148240, PR2852: aarch64: random infrequent NULL
    pointer exceptions in javac

  - PPC & AIX port

  - S8034797, PR2851: AIX: Fix os::naked_short_sleep() in
    os_aix.cpp after 8028280

  - S8139258, PR2851: PPC64LE: argument passing problem when
    passing 15 floats in native call

  - S8139421, PR2851: PPC64LE:
    MacroAssembler::bxx64_patchable kill register R12

Update to 2.6.5 - OpenJDK 7u99 (bsc#972468)

  - Security fixes

  - S8152335, CVE-2016-0636: Improve MethodHandle
    consistency

  - Import of OpenJDK 7 u99 build 0

  - S6425769, PR2858: Allow specifying an address to bind
    JMX remote connector

  - S6961123: setWMClass fails to null-terminate WM_CLASS
    string

  - S8145982, PR2858: JMXInterfaceBindingTest is failing
    intermittently

  - S8146015, PR2858: JMXInterfaceBindingTest is failing
    intermittently for IPv6 addresses

  - Backports

  - S8028727, PR2814: [parfait] warnings from b116 for
    jdk.src.share.native.sun.security.ec: JNI pending
    exceptions

  - S8048512, PR2814: Uninitialised memory in
    jdk/src/share/native/sun/security/ec/ECC_JNI.cpp

  - S8071705. PR2819, RH1182694: Java application menu
    misbehaves when running multiple screen stacked
    vertically

  - S8150954, PR2866, RH1176206: AWT Robot not compatible
    with GNOME Shell

  - Bug fixes

  - PR2803: Make system CUPS optional

  - PR2886: Location of 'stap' executable is hard-coded

  - PR2893: test/tapset/jstaptest.pl should be executable

  - PR2894: Add missing test directory in make check.

  - CACAO

  - PR2781, CA195: typeinfo.cpp: typeinfo_merge_nonarrays:
    Assertion `dest && result && x.any && y.any' failed

  - AArch64 port

  - PR2852: Add support for large code cache

  - PR2852: Apply ReservedCodeCacheSize default limiting to
    AArch64 only.

  - S8081289, PR2852: aarch64: add support for
    RewriteFrequentPairs in interpreter

  - S8131483, PR2852: aarch64: illegal stlxr instructions

  - S8133352, PR2852: aarch64: generates constrained
    unpredictable instructions

  - S8133842, PR2852: aarch64: C2 generates illegal
    instructions with int shifts >=32

  - S8134322, PR2852: AArch64: Fix several errors in C2
    biased locking implementation

  - S8136615, PR2852: aarch64: elide DecodeN when followed
    by CmpP 0

  - S8138575, PR2852: Improve generated code for profile
    counters

  - S8138641, PR2852: Disable C2 peephole by default for
    aarch64

  - S8138966, PR2852: Intermittent SEGV running ParallelGC

  - S8143067, PR2852: aarch64: guarantee failure in javac

  - S8143285, PR2852: aarch64: Missing load acquire when
    checking if ConstantPoolCacheEntry is resolved

  - S8143584, PR2852: Load constant pool tag and class
    status with load acquire

  - S8144201, PR2852: aarch64:
    jdk/test/com/sun/net/httpserver/Test6a.java fails with

    --enable-unlimited-crypto

  - S8144582, PR2852: AArch64 does not generate correct
    branch profile data

  - S8146709, PR2852: AArch64: Incorrect use of ADRP for
    byte_map_base

  - S8147805, PR2852: aarch64: C1 segmentation fault due to
    inline Unsafe.getAndSetObject

  - S8148240, PR2852: aarch64: random infrequent NULL
    pointer exceptions in javac

  - PPC & AIX port

  - S8034797, PR2851: AIX: Fix os::naked_short_sleep() in
    os_aix.cpp after 8028280

  - S8139258, PR2851: PPC64LE: argument passing problem when
    passing 15 floats in native call

  - S8139421, PR2851: PPC64LE:
    MacroAssembler::bxx64_patchable kill register R12

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972468"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_7_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-bootstrap-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-1.7.0.99-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-accessibility-1.7.0.99-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-bootstrap-1.7.0.99-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-bootstrap-debuginfo-1.7.0.99-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-bootstrap-debugsource-1.7.0.99-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-bootstrap-devel-1.7.0.99-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-bootstrap-devel-debuginfo-1.7.0.99-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-bootstrap-headless-1.7.0.99-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-bootstrap-headless-debuginfo-1.7.0.99-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.99-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-debugsource-1.7.0.99-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-demo-1.7.0.99-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.99-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-devel-1.7.0.99-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.99-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-headless-1.7.0.99-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.99-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-javadoc-1.7.0.99-28.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-src-1.7.0.99-28.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_0-openjdk-bootstrap / etc");
}
