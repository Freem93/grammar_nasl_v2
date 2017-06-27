#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1389.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95549);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/12/06 14:24:42 $");

  script_cve_id("CVE-2016-5542", "CVE-2016-5554", "CVE-2016-5556", "CVE-2016-5568", "CVE-2016-5573", "CVE-2016-5582", "CVE-2016-5597");

  script_name(english:"openSUSE Security Update : java-1_7_0-openjdk (openSUSE-2016-1389)");
  script_summary(english:"Check for the openSUSE-2016-1389 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Update to 2.6.8 - OpenJDK 7u121

  - Security fixes

  + S8151921: Improved page resolution

  + S8155968: Update command line options

  + S8155973, CVE-2016-5542: Tighten jar checks
    (boo#1005522)

  + S8157176: Improved classfile parsing

  + S8157739, CVE-2016-5554: Classloader Consistency
    Checking (boo#1005523)

  + S8157749: Improve handling of DNS error replies

  + S8157753: Audio replay enhancement

  + S8157759: LCMS Transform Sampling Enhancement

  + S8157764: Better handling of interpolation plugins

  + S8158302: Handle contextual glyph substitutions

  + S8158993, CVE-2016-5568: Service Menu services
    (boo#1005525)

  + S8159495: Fix index offsets

  + S8159503: Amend Annotation Actions

  + S8159511: Stack map validation

  + S8159515: Improve indy validation

  + S8159519, CVE-2016-5573: Reformat JDWP messages
    (boo#1005526)

  + S8160090: Better signature handling in pack200

  + S8160094: Improve pack200 layout

  + S8160098: Clean up color profiles

  + S8160591, CVE-2016-5582: Improve internal array handling
    (boo#1005527)

  + S8160838, CVE-2016-5597: Better HTTP service
    (boo#1005528)

  + PR3207, RH1367357: lcms2: Out-of-bounds read in
    Type_MLU_Read()

  + CVE-2016-5556 (boo#1005524)

  - Import of OpenJDK 7 u121 build 0

  + S6624200: Regression test fails:
    test/closed/javax/swing/JMenuItem/4654927/bug4654927.jav
    a

  + S6882559: new JEditorPane('text/plain','') fails for
    null context class loader

  + S7090158: Networking Libraries don't build with javac
    -Werror

  + S7125055: ContentHandler.getContent API changed in error

  + S7145960: sun/security/mscapi/ShortRSAKey1024.sh failing
    on windows

  + S7187051: ShortRSAKeynnn.sh tests should do cleanup
    before start test

  + S8000626: Implement dead key detection for KeyEvent on
    Linux

  + S8003890: corelibs test scripts should pass TESTVMOPTS

  + S8005629: javac warnings compiling
    java.awt.EventDispatchThread and sun.awt.X11.XIconWindow

  + S8010297: Missing isLoggable() checks in logging code

  + S8010782: clean up source files containing carriage
    return characters

  + S8014431: cleanup warnings indicated by the
    -Wunused-value compiler option on linux

  + S8015265: revise the fix for 8007037

  + S8016747: Replace deprecated PlatformLogger
    isLoggable(int) with isLoggable(Level)

  + S8020708: NLS mnemonics missing in
    SwingSet2/JInternalFrame demo

  + S8024756: method grouping tabs are not selectable

  + S8026741: jdk8 l10n resource file translation update 5

  + S8048147: Privilege tests with JAAS Subject.doAs

  + S8048357: PKCS basic tests

  + S8049171: Additional tests for jarsigner's warnings

  + S8059177: jdk8u40 l10n resource file translation update
    1

  + S8075584: test for 8067364 depends on hardwired text
    advance

  + S8076486: [TESTBUG]
    javax/security/auth/Subject/doAs/NestedActions.java
    fails if extra VM options are given

  + S8077953: [TEST_BUG]
    com/sun/management/OperatingSystemMXBean/TestTotalSwap.j
    ava Compilation failed after JDK-8077387

  + S8080628: No mnemonics on Open and Save buttons in
    JFileChooser

  + S8083601: jdk8u60 l10n resource file translation update
    2

  + S8140530: Creating a VolatileImage with size 0,0 results
    in no longer working g2d.drawString

  + S8142926: OutputAnalyzer's shouldXXX() calls return this

  + S8143134: L10n resource file translation update

  + S8147077: IllegalArgumentException thrown by
    api/java_awt/Component/FlipBufferStrategy/indexTGF_Gener
    al

  + S8148127: IllegalArgumentException thrown by JCK test
    api/java_awt/Component/FlipBufferStrategy/indexTGF_Gener
    al in opengl pipeline

  + S8150611: Security problem on
    sun.misc.resources.Messages*

  + S8157653: [Parfait] Uninitialised variable in
    awt_Font.cpp

  + S8158734: JEditorPane.createEditorKitForContentType
    throws NPE after 6882559

  + S8159684: (tz) Support tzdata2016f

  + S8160934: isnan() is not available on older MSVC
    compilers

  + S8162411: Service Menu services 2

  + S8162419:
    closed/com/oracle/jfr/runtime/TestVMInfoEvent.sh failing
    after JDK-8155968

  + S8162511: 8u111 L10n resource file updates

  + S8162792: Remove constraint DSA keySize < 1024 from
    jdk.jar.disabledAlgorithms in jdk8

  + S8164452: 8u111 L10n resource file update - msgdrop 20

  + S8165816: jarsigner -verify shows jar unsigned if it was
    signed with a weak algorithm

  + S8166381: Back out changes to the java.security file to
    not disable MD5

  - Backports

  + S6604109, PR3162:
    javax.print.PrintServiceLookup.lookupPrintServices fails
    SOMETIMES for Cups

  + S6907252, PR3162: ZipFileInputStream Not Thread-Safe

  + S8024046, PR3162: Test
    sun/security/krb5/runNameEquals.sh failed on 7u45
    Embedded linux-ppc*

  + S8028479, PR3162: runNameEquals still cannot precisely
    detect if a usable native krb5 is available

  + S8034057, PR3162: Files.getFileStore and
    Files.isWritable do not work with SUBST'ed drives (win)

  + S8038491, PR3162: Improve synchronization in
    ZipFile.read()

  + S8038502, PR3162: Deflater.needsInput() should use
    synchronization

  + S8059411, PR3162: RowSetWarning does not correctly chain
    warnings

  + S8062198, PR3162: Add RowSetMetaDataImpl Tests and add
    column range validation to isdefinitlyWritable

  + S8066188, PR3162: BaseRowSet returns the wrong default
    value for escape processing

  + S8072466, PR3162: Deadlock when initializing
    MulticastSocket and DatagramSocket

  + S8075118, PR3162: JVM stuck in infinite loop during
    verification

  + S8076579, PR3162: Popping a stack frame after exception
    breakpoint sets last method param to exception

  + S8078495, PR3162: End time checking for native TGT is
    wrong

  + S8078668, PR3162: jar usage string mentions unsupported
    option '-n'

  + S8080115, PR3162: (fs) Crash in libgio when calling
    Files.probeContentType(path) from parallel threads

  + S8081794, PR3162: ParsePosition getErrorIndex returns 0
    for TimeZone parsing problem

  + S8129957, PR3162: Deadlock in JNDI LDAP implementation
    when closing the LDAP context

  + S8130136, PR3162: Swing window sometimes fails to
    repaint partially when it becomes exposed

  + S8130274, PR3162: java/nio/file/FileStore/Basic.java
    fails when two successive stores in an iteration are
    determined to be equal

  + S8132551, PR3162: Initialize local variables before
    returning them in p11_convert.c

  + S8133207, PR3162: [TEST_BUG] ParallelProbes.java test
    fails after changes for JDK-8080115

  + S8133666, PR3162: OperatingSystemMXBean reports
    abnormally high machine CPU consumption on Linux

  + S8135002, PR3162: Fix or remove broken links in
    objectMonitor.cpp comments

  + S8137121, PR3162: (fc) Infinite loop
    FileChannel.truncate

  + S8137230, PR3162: TEST_BUG:
    java/nio/channels/FileChannel/LoopingTruncate.java timed
    out

  + S8139373, PR3162: [TEST_BUG]
    java/net/MulticastSocket/MultiDead.java failed with
    timeout

  + S8140249, PR3162: JVM Crashing During startUp If Flight
    Recording is enabled

  + S8141491, PR3160, G592292: Unaligned memory access in
    Bits.c

  + S8144483, PR3162: One long Safepoint pause directly
    after each GC log rotation

  + S8149611, PR3160, G592292: Add tests for
    Unsafe.copySwapMemory

  - Bug fixes

  + S8078628, PR3151: Zero build fails with pre-compiled
    headers disabled

  + PR3128: pax-mark-vm script calls 'exit -1' which is
    invalid in dash

  + PR3131: PaX marking fails on filesystems which don't
    support extended attributes

  + PR3135: Makefile.am rule
    stamps/add/tzdata-support-debug.stamp has a typo in
    add-tzdata dependency

  + PR3141: Pass $(CC) and $(CXX) to OpenJDK build

  + PR3166: invalid zip timestamp handling leads to error
    building bootstrap-javac

  + PR3202: Update infinality configure test

  + PR3212: Disable ARM32 JIT by default

  - CACAO

  + PR3136: CACAO is broken due to 2 new native methods in
    sun.misc.Unsafe (from S8158260)

  - JamVM

  + PR3134: JamVM is broken due to 2 new native methods in
    sun.misc.Unsafe (from S8158260)

  - AArch64 port

  + S8167200, PR3204: AArch64: Broken stack pointer
    adjustment in interpreter

  + S8168888: Port 8160591: Improve internal array handling
    to AArch64.

  + PR3211: AArch64 build fails with pre-compiled headers
    disabled

  - Changed patch :

  - java-1_7_0-openjdk-gcc6.patch

  + Rediff to changed context

  - Disable arm32 JIT, since its build broken
    (http://icedtea.classpath.org/bugzilla/show_bug.cgi?id=2
    942)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://icedtea.classpath.org/bugzilla/show_bug.cgi?id=2942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005528"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/06");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-1.7.0.121-24.42.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-accessibility-1.7.0.121-24.42.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.121-24.42.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-debugsource-1.7.0.121-24.42.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-demo-1.7.0.121-24.42.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.121-24.42.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-devel-1.7.0.121-24.42.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.121-24.42.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-headless-1.7.0.121-24.42.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.121-24.42.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-javadoc-1.7.0.121-24.42.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-src-1.7.0.121-24.42.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_0-openjdk / java-1_7_0-openjdk-accessibility / etc");
}
