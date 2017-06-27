#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1400-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(100409);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/25 13:29:27 $");

  script_cve_id("CVE-2017-3289", "CVE-2017-3509", "CVE-2017-3511", "CVE-2017-3512", "CVE-2017-3514", "CVE-2017-3526", "CVE-2017-3533", "CVE-2017-3539", "CVE-2017-3544");
  script_osvdb_id(150415, 152319, 155830, 155831, 155832, 155833, 155834, 155835, 155836, 155837);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : java-1_7_0-openjdk (SUSE-SU-2017:1400-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_7_0-openjdk fixes the following issues :

  - Update to 2.6.10 - OpenJDK 7u141 (bsc#1034849)

  - Security fixes

  - S8163520, CVE-2017-3509: Reuse cache entries

  - S8163528, CVE-2017-3511: Better library loading

  - S8165626, CVE-2017-3512: Improved window framing

  - S8167110, CVE-2017-3514: Windows peering issue

  - S8169011, CVE-2017-3526: Resizing XML parse trees

  - S8170222, CVE-2017-3533: Better transfers of files

  - S8171121, CVE-2017-3539: Enhancing jar checking

  - S8171533, CVE-2017-3544: Better email transfer

  - S8172299: Improve class processing

  - New features

  - PR3347: jstack.stp should support AArch64

  - Import of OpenJDK 7 u141 build 0

  - S4717864: setFont() does not update Fonts of Menus
    already on screen

  - S6474807: (smartcardio) CardTerminal.connect() throws
    CardException instead of CardNotPresentException

  - S6518907: cleanup IA64 specific code in Hotspot

  - S6869327: Add new C2 flag to keep safepoints in counted
    loops.

  - S7112912: Message 'Error occurred during initialization
    of VM' on boxes with lots of RAM

  - S7124213: [macosx] pack() does ignore size of a
    component; doesn't on the other platforms

  - S7124219: [macosx] Unable to draw images to fullscreen

  - S7124552: [macosx] NullPointerException in
    getBufferStrategy()

  - S7148275: [macosx] setIconImages() not working correctly
    (distorted icon when minimized)

  - S7154841: [macosx] Popups appear behind taskbar

  - S7155957:
    closed/java/awt/MenuBar/MenuBarStress1/MenuBarStress1.ja
    va hangs on win 64 bit with jdk8

  - S7160627: [macosx] TextArea has wrong initial size

  - S7167293: FtpURLConnection connection leak on
    FileNotFoundException

  - S7168851: [macosx] Netbeans crashes in
    CImage.nativeCreateNSImageFromArray

  - S7197203: sun/misc/URLClassPath/ClassnameCharTest.sh
    failed, compile error

  - S8005255: [macosx] Cleanup warnings in sun.lwawt

  - S8006088: Incompatible heap size flags accepted by VM

  - S8007295: Reduce number of warnings in awt classes

  - S8010722: assert: failed: heap size is too big for
    compressed oops

  - S8011059: [macosx] Support automatic @2x images loading
    on Mac OS X

  - S8014058: Regression tests for 8006088

  - S8014489:
    tests/gc/arguments/Test(Serial|CMS|Parallel|G1)HeapSizeF
    lags jtreg tests invoke wrong class

  - S8016302: Change type of the number of GC workers to
    unsigned int (2)

  - S8024662: gc/arguments/TestUseCompressedOopsErgo.java
    does not compile.

  - S8024669: Native OOME when allocating after changes to
    maximum heap supporting Coops sizing on sparcv9

  - S8024926: [macosx] AquaIcon HiDPI support

  - S8025974: l10n for policytool

  - S8027025: [macosx] getLocationOnScreen returns 0 if
    parent invisible

  - S8028212: Custom cursor HiDPI support

  - S8028471: PPC64 (part 215): opto: Extend
    ImplicitNullCheck optimization.

  - S8031573: [macosx] Checkmarks of JCheckBoxMenuItems
    aren't rendered in high resolution on Retina

  - S8033534: [macosx] Get MultiResolution image from native
    system

  - S8033786: White flashing when opening Dialogs and Menus
    using Nimbus with dark background

  - S8035568: [macosx] Cursor management unification

  - S8041734: JFrame in full screen mode leaves empty
    workspace after close

  - S8059803: Update use of GetVersionEx to get correct
    Windows version in hs_err files

  - S8066504: GetVersionEx in
    java.base/windows/native/libjava/java_props_md.c might
    not get correct Windows version 0

  - S8079595: Resizing dialog which is JWindow parent makes
    JVM crash

  - S8080729: [macosx] java 7 and 8 JDialogs on multiscreen
    jump to parent frame on focus

  - S8130769: The new menu can't be shown on the menubar
    after clicking the 'Add' button.

  - S8133357: 8u65 l10n resource file translation update

  - S8146602:
    jdk/test/sun/misc/URLClassPath/ClassnameCharTest.java
    test fails with NullPointerException

  - S8147842: IME Composition Window is displayed at
    incorrect location

  - S8147910: Cache initial active_processor_count

  - S8150490: Update OS detection code to recognize Windows
    Server 2016

  - S8161147: jvm crashes when -XX:+UseCountedLoopSafepoints
    is enabled

  - S8161195: Regression:
    closed/javax/swing/text/FlowView/LayoutTest.java

  - S8161993: G1 crashes if active_processor_count changes
    during startup

  - S8162603: Unrecognized VM option
    'UseCountedLoopSafepoints'

  - S8162876: [TEST_BUG]
    sun/net/www/protocol/http/HttpInputStream.java fails
    intermittently

  - S8164533:
    sun/security/ssl/SSLSocketImpl/CloseSocket.java failed
    with 'Error while cleaning up threads after test'

  - S8167179: Make XSL generated namespace prefixes local to
    transformation process

  - S8169465: Deadlock in com.sun.jndi.ldap.pool.Connections

  - S8169589: [macosx] Activating a JDialog puts to back
    another dialog

  - S8170307: Stack size option -Xss is ignored

  - S8170316: (tz) Support tzdata2016j

  - S8170814: Reuse cache entries (part II)

  - S8171388: Update JNDI Thread contexts

  - S8171949: [macosx] AWT_ZoomFrame Automated tests fail
    with error: The bitwise mask Frame.ICONIFIED is not
    setwhen the frame is in ICONIFIED state

  - S8171952: [macosx]
    AWT_Modality/Automated/ModalExclusion/NoExclusion/Modele
    ssDialog test fails as DummyButton on Dialog did not
    gain focus when clicked.

  - S8173931: 8u131 L10n resource file update

  - S8174844: Incorrect GPL header causes RE script to miss
    swap to commercial header for licensee source bundle

  - S8175087: [bsd] Fix build after '8024900: PPC64: Enable
    new build on AIX (jdk part)'

  - S8175163: [bsd] Fix build after '8005629: javac warnings
    compiling java.awt.EventDispatchThread...'

  - S8176044: (tz) Support tzdata2017a

  - Import of OpenJDK 7 u141 build 1

  - S8043723: max_heap_for_compressed_oops() declared with
    size_t, but defined with uintx

  - Import of OpenJDK 7 u141 build 2

  - S8011123: serialVersionUID of
    java.awt.dnd.InvalidDnDOperationException changed in
    JDK8-b82

  - Backports

  - S6515172, PR3362: Runtime.availableProcessors() ignores
    Linux taskset command

  - S8022284, PR3209: Hide internal data structure in
    PhaseCFG

  - S8023003, PR3209: Cleanup the public interface to
    PhaseCFG

  - S8023691, PR3209: Create interface for nodes in class
    Block

  - S8023988, PR3209: Move local scheduling of nodes to the
    CFG creation and code motion phase (PhaseCFG)

  - S8043780, PR3369: Use open(O_CLOEXEC) instead of
    fcntl(FD_CLOEXEC)

  - S8157306, PR3209: Random infrequent NULL pointer
    exceptions in javac

  - S8173783, PR3329: IllegalArgumentException:
    jdk.tls.namedGroups

  - S8173941, PR3330: SA does not work if executable is DSO

  - S8174729, PR3361: Race Condition in
    java.lang.reflect.WeakCache

  - Bug fixes

  - PR3349: Architectures unsupported by SystemTap tapsets
    throw a parse error

  - PR3370: Disable ARM32 JIT by default in
    jdk_generic_profile.sh

  - PR3379: Perl should be mandatory

  - PR3390: javac.in and javah.in should use @PERL@ rather
    than a hard-coded path

  - CACAO

  - PR2732: Raise javadoc memory limits for CACAO again!

  - AArch64 port

  - S8177661, PR3367: Correct ad rule output register types
    from iRegX to iRegXNoSp

  - Get ecj.jar path from gcj, use the gcc variant that
    provides Java to build C code to make sure jni.h is
    available.

  - S8167104, CVE-2017-3289: Additional class construction

  - S6253144: Long narrowing conversion should describe the

  - S6328537: Improve javadocs for Socket class by adding

  - S6978886: javadoc shows stacktrace after print error

  - S6995421: Eliminate the static dependency to

  - S7027045: (doc) java/awt/Window.java has several typos
    in

  - S7054969: Null-check-in-finally pattern in java/security

  - S7072353: JNDI libraries do not build with javac
    -Xlint:all

  - S7092447: Clarify the default locale used in each locale

  - S7103570: AtomicIntegerFieldUpdater does not work when

  - S7187144: JavaDoc for ScriptEngineFactory.getProgram()

  - S8000418: javadoc should used a standard 'generated by

  - S8000666: javadoc should write directly to Writer
    instead of

  - S8000970: break out auxiliary classes that will prevent

  - S8001669: javadoc internal DocletAbortException should
    set

  - S8011402: Move blacklisting certificate logic from hard
    code

  - S8011547: Update XML Signature implementation to Apache

  - S8012288: XML DSig API allows wrong tag names and extra

  - S8017325: Cleanup of the javadoc <code> tag in

  - S8017326: Cleanup of the javadoc <code> tag in

  - S8019772: Fix doclint issues in javax.crypto and

  - S8020688: Broken links in documentation at

  - S8021108: Clean up doclint warnings and errors in
    java.text

  - S8022120: JCK test
    api/javax_xml/crypto/dsig/TransformService/index_ParamMe
    thods

  - S8025409: Fix javadoc comments errors and warning
    reported by

  - S8026021: more fix of javadoc errors and warnings
    reported by

  - S8037099: [macosx] Remove all references to GC from
    native

  - S8038184: XMLSignature throws
    StringIndexOutOfBoundsException

  - S8038349: Signing XML with DSA throws Exception when key
    is

  - S8049244: XML Signature performance issue caused by

  - S8050893: (smartcardio) Invert reset argument in tests
    in

  - S8059212: Modify sun/security/smartcardio manual
    regression

  - S8068279: (typo in the spec)

  - S8068491: Update the protocol for references of

  - S8069038: javax/net/ssl/TLS/TLSClientPropertyTest.java
    needs

  - S8076369: Introduce the jdk.tls.client.protocols system

  - S8139565: Restrict certificates with DSA keys less than
    1024

  - S8140422: Add mechanism to allow non default root CAs to
    be

  - S8140587: Atomic*FieldUpdaters should use
    Class.isInstance

  - S8149029: Secure validation of XML based digital
    signature

  - S8151893: Add security property to configure XML
    Signature

  - S8161228: URL objects with custom protocol handlers have
    port

  - S8163304: jarsigner -verbose -verify should print the

  - S8164908: ReflectionFactory support for IIOP and custom

  - S8165230: RMIConnection addNotificationListeners failing
    with

  - S8166393: disabledAlgorithms property should not be
    strictly

  - S8166591: [macos 10.12] Trackpad scrolling of text on OS
    X

  - S8166739: Improve extensibility of ObjectInputFilter

  - S8167356: Follow up fix for jdk8 backport of 8164143.
    Changes

  - S8167459: Add debug output for indicating if a chosen

  - S8168861: AnchorCertificates uses hard-coded password
    for

  - S8169688: Backout (remove) MD5 from

  - S8169911: Enhanced tests for jarsigner -verbose -verify
    after

  - S8170131: Certificates not being blocked by

  - S8173854: [TEST] Update DHEKeySizing test case following

  - S7102489, PR3316, RH1390708: RFE: cleanup jlong typedef
    on

  - S8000351, PR3316, RH1390708: Tenuring threshold should
    be

  - S8153711, PR3315, RH1284948: [REDO] JDWP: Memory Leak :

  - S8170888, PR3316, RH1390708: [linux] Experimental
    support for

  - PR3318: Replace 'infinality' with 'improved font
    rendering'

  - PR3324: Fix NSS_LIBDIR substitution in

  - S8165673, PR3320: AArch64: Fix JNI floating point
    argument

  + S6604109, PR3162 :

  - Add -fno-delete-null-pointer-checks -fno-lifetime-dse to
    try to directory to be specified versions of
    IcedTea</code></code>

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1034849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3289.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3509.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3511.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3512.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3514.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3526.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3533.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3539.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-3544.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171400-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0b545974"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-864=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-864=1

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2017-864=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-864=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2017-864=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1/2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-debugsource-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-demo-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-devel-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-headless-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-debugsource-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-demo-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-devel-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"java-1_7_0-openjdk-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"java-1_7_0-openjdk-debugsource-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-debugsource-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-1.7.0.141-42.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.141-42.1")) flag++;


if (flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
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
