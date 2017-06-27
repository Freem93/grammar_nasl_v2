#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-977.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(92978);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:37:13 $");

  script_cve_id("CVE-2016-3458", "CVE-2016-3485", "CVE-2016-3498", "CVE-2016-3500", "CVE-2016-3503", "CVE-2016-3508", "CVE-2016-3511", "CVE-2016-3550", "CVE-2016-3598", "CVE-2016-3606", "CVE-2016-3610");

  script_name(english:"openSUSE Security Update : java-1_7_0-openjdk (openSUSE-2016-977)");
  script_summary(english:"Check for the openSUSE-2016-977 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_7_0-openjdk fixes the following issues :

  - Update to 2.6.7 - OpenJDK 7u111

  - Security fixes

  - S8079718, CVE-2016-3458: IIOP Input Stream Hooking
    (bsc#989732)

  - S8145446, CVE-2016-3485: Perfect pipe placement (Windows
    only) (bsc#989734)

  - S8147771: Construction of static protection domains
    under Javax custom policy

  - S8148872, CVE-2016-3500: Complete name checking
    (bsc#989730)

  - S8149962, CVE-2016-3508: Better delineation of XML
    processing (bsc#989731)

  - S8150752: Share Class Data

  - S8151925: Font reference improvements

  - S8152479, CVE-2016-3550: Coded byte streams (bsc#989733)

  - S8155981, CVE-2016-3606: Bolster bytecode verification
    (bsc#989722)

  - S8155985, CVE-2016-3598: Persistent Parameter Processing
    (bsc#989723)

  - S8158571, CVE-2016-3610: Additional method handle
    validation (bsc#989725)

  - CVE-2016-3511 (bsc#989727)

  - CVE-2016-3503 (bsc#989728)

  - CVE-2016-3498 (bsc#989729)

  - Import of OpenJDK 7 u111 build 0

  - S6953295: Move few sun.security.{util, x509, pkcs}
    classes used by keytool/jarsigner to another package

  - S7060849: Eliminate pack200 build warnings

  - S7064075: Security libraries don't build with javac
    -Xlint:all,-deprecation -Werror

  - S7069870: Parts of the JDK erroneously rely on generic
    array initializers with diamond

  - S7102686: Restructure timestamp code so that jars and
    modules can more easily share the same code

  - S7105780: Add SSLSocket client/SSLEngine server to
    templates directory

  - S7142339: PKCS7.java is needlessly creating SHA1PRNG
    SecureRandom instances when timestamping is not done

  - S7152582: PKCS11 tests should use the NSS libraries
    available in the OS

  - S7192202: Make sure keytool prints both unknown and
    unparseable extensions

  - S7194449: String resources for Key Tool and Policy Tool
    should be in their respective packages

  - S7196855: autotest.sh fails on ubuntu because
    libsoftokn.so not found

  - S7200682: TEST_BUG: keytool/autotest.sh still has
    problems with libsoftokn.so

  - S8002306: (se) Selector.open fails if invoked with
    thread interrupt status set [win]

  - S8009636: JARSigner including TimeStamp PolicyID
    (TSAPolicyID) as defined in RFC3161

  - S8019341: Update CookieHttpsClientTest to use the newer
    framework.

  - S8022228: Intermittent test failures in
    sun/security/ssl/javax/net/ssl/NewAPIs

  - S8022439: Fix lint warnings in sun.security.ec

  - S8022594: Potential deadlock in <clinit> of
    sun.nio.ch.Util/IOUtil

  - S8023546: sun/security/mscapi/ShortRSAKey1024.sh fails
    intermittently

  - S8036612: [parfait] JNI exception pending in
    jdk/src/windows/native/sun/security/mscapi/security.cpp

  - S8037557: test SessionCacheSizeTests.java timeout

  - S8038837: Add support to jarsigner for specifying
    timestamp hash algorithm

  - S8079410: Hotspot version to share the same update and
    build version from JDK

  - S8130735: javax.swing.TimerQueue: timer fires late when
    another timer starts

  - S8139436: sun.security.mscapi.KeyStore might load
    incomplete data

  - S8144313: Test SessionTimeOutTests can be timeout

  - S8146387: Test SSLSession/SessionCacheSizeTests socket
    accept timed out

  - S8146669: Test SessionTimeOutTests fails intermittently

  - S8146993: Several javax/management/remote/mandatory
    regression tests fail after JDK-8138811

  - S8147857: [TEST] RMIConnector logs attribute names
    incorrectly

  - S8151841, PR3098: Build needs additional flags to
    compile with GCC 6

  - S8151876: (tz) Support tzdata2016d

  - S8157077: 8u101 L10n resource file updates

  - S8161262: Fix jdk build with gcc 4.1.2:
    -fno-strict-overflow not known.

  - Import of OpenJDK 7 u111 build 1

  - S7081817:
    test/sun/security/provider/certpath/X509CertPath/Illegal
    Certificates.java failing

  - S8140344: add support for 3 digit update release numbers

  - S8145017: Add support for 3 digit hotspot minor version
    numbers

  - S8162344: The API changes made by CR 7064075 need to be
    reverted

  - Backports

  - S2178143, PR2958: JVM crashes if the number of bound
    CPUs changed during runtime

  - S4900206, PR3101: Include worst-case rounding tests for
    Math library functions

  - S6260348, PR3067: GTK+ L&F JTextComponent not respecting
    desktop caret blink rate

  - S6934604, PR3075: enable parts of EliminateAutoBox by
    default

  - S7043064, PR3020: sun/java2d/cmm/ tests failed against
    RI b141 & b138-nightly

  - S7051394, PR3020: NullPointerException when running
    regression tests LoadProfileTest by using openjdk-7-b144

  - S7086015, PR3013: fix
    test/tools/javac/parser/netbeans/JavacParserTest.java

  - S7119487, PR3013: JavacParserTest.java test fails on
    Windows platforms

  - S7124245, PR3020: [lcms] ColorConvertOp to color space
    CS_GRAY apparently converts orange to 244,244,0

  - S7159445, PR3013: (javac) emits inaccurate diagnostics
    for enhanced for-loops

  - S7175845, PR1437, RH1207129: 'jar uf' changes file
    permissions unexpectedly

  - S8005402, PR3020: Need to provide benchmarks for color
    management

  - S8005530, PR3020: [lcms] Improve performance of
    ColorConverOp for default destinations

  - S8005930, PR3020: [lcms] ColorConvertOp: Alpha channel
    is not transferred from source to destination.

  - S8013430, PR3020: REGRESSION:
    closed/java/awt/color/ICC_Profile/LoadProfileTest/LoadPr
    ofileTest.java fails with
    java.io.StreamCorruptedException: invalid type code: EE
    since 8b87

  - S8014286, PR3075: failed java/lang/Math/DivModTests.java
    after 6934604 changes

  - S8014959, PR3075:
    assert(Compile::current()->live_nodes() <
    (uint)MaxNodeLimit) failed: Live Node limit exceeded
    limit

  - S8019247, PR3075: SIGSEGV in compiled method
    c8e.e.t_.getArray(Ljava/lang/Class;)[Ljava/lang/Object

  - S8024511, PR3020: Crash during color profile destruction

  - S8025429, PR3020: [parfait] warnings from b107 for
    sun.java2d.cmm: JNI exception pending

  - S8026702, PR3020: Fix for 8025429 breaks jdk build on
    windows

  - S8026780, PR3020, RH1142587: Crash on PPC and PPC v2 for
    Java_awt test suit

  - S8047066, PR3020: Test
    test/sun/awt/image/bug8038000.java fails with
    ClassCastException

  - S8069181, PR3012, RH1015612: java.lang.AssertionError
    when compiling JDK 1.4 code in JDK 8

  - S8158260, PR2992, RH1341258: PPC64: unaligned
    Unsafe.getInt can lead to the generation of illegal
    instructions (bsc#988651)

  - S8159244, PR3075: Partially initialized string object
    created by C2's string concat optimization may escape

  - Bug fixes

  - PR2799, RH1195203: Files are missing from resources.jar

  - PR2900: Don't use WithSeed versions of NSS functions as
    they don't fully process the seed

  - PR3091: SystemTap is heavily confused by multiple JDKs

  - PR3102: Extend 8022594 to AixPollPort

  - PR3103: Handle case in clean-fonts where
    linux.fontconfig.Gentoo.properties.old has not been
    created

  - PR3111: Provide option to disable SystemTap tests

  - PR3114: Don't assume system mime.types supports
    text/x-java-source

  - PR3115: Add check for elliptic curve cryptography
    implementation

  - PR3116: Add tests for Java debug info and source files

  - PR3118: Path to agpl-3.0.txt not updated

  - PR3119: Makefile handles cacerts as a symlink, but the
    configure check doesn't

  - AArch64 port

  - S8148328, PR3100: aarch64: redundant lsr instructions in
    stub code.

  - S8148783, PR3100: aarch64: SEGV running SpecJBB2013

  - S8148948, PR3100: aarch64: generate_copy_longs calls
    align() incorrectly

  - S8150045, PR3100: arraycopy causes segfaults in SATB
    during garbage collection

  - S8154537, PR3100: AArch64: some integer rotate
    instructions are never emitted

  - S8154739, PR3100: AArch64: TemplateTable::fast_xaccess
    loads in wrong mode

  - S8157906, PR3100: aarch64: some more integer rotate
    instructions are never emitted

  - Enable SunEC for SLE12 and Leap (bsc#982366)

  - Fix aarch64 running with 48 bits va space (bsc#984684)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989734"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_7_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/16");
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

if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-1.7.0.111-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-accessibility-1.7.0.111-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-bootstrap-1.7.0.111-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-bootstrap-debuginfo-1.7.0.111-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-bootstrap-debugsource-1.7.0.111-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-bootstrap-devel-1.7.0.111-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-bootstrap-devel-debuginfo-1.7.0.111-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-bootstrap-headless-1.7.0.111-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-bootstrap-headless-debuginfo-1.7.0.111-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.111-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-debugsource-1.7.0.111-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-demo-1.7.0.111-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.111-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-devel-1.7.0.111-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.111-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-headless-1.7.0.111-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.111-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-javadoc-1.7.0.111-34.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_7_0-openjdk-src-1.7.0.111-34.1") ) flag++;

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
