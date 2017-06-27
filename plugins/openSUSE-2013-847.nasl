#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-847.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75196);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-3829", "CVE-2013-4002", "CVE-2013-5772", "CVE-2013-5774", "CVE-2013-5778", "CVE-2013-5780", "CVE-2013-5782", "CVE-2013-5783", "CVE-2013-5784", "CVE-2013-5790", "CVE-2013-5797", "CVE-2013-5800", "CVE-2013-5802", "CVE-2013-5803", "CVE-2013-5804", "CVE-2013-5805", "CVE-2013-5806", "CVE-2013-5809", "CVE-2013-5814", "CVE-2013-5817", "CVE-2013-5820", "CVE-2013-5823", "CVE-2013-5825", "CVE-2013-5829", "CVE-2013-5830", "CVE-2013-5840", "CVE-2013-5842", "CVE-2013-5849", "CVE-2013-5850", "CVE-2013-5851");

  script_name(english:"openSUSE Security Update : java-1_7_0-openjdk (openSUSE-SU-2013:1663-1)");
  script_summary(english:"Check for the openSUSE-2013-847 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to icedtea 2.4.3 (bnc#846999) synchronized OpenJDK 7 support
with the upstream u45 b31 fixes the following issues :

  - S8006900, CVE-2013-3829: Add new date/time capability

  - S8008589: Better MBean permission validation

  - S8011071, CVE-2013-5780: Better crypto provider handling

  - S8011081, CVE-2013-5772: Improve jhat

  - S8011157, CVE-2013-5814: Improve CORBA portablility

  - S8012071, CVE-2013-5790: Better Building of Beans

  - S8012147: Improve tool support

  - S8012277: CVE-2013-5849: Improve AWT DataFlavor

  - S8012425, CVE-2013-5802: Transform TransformerFactory

  - S8013503, CVE-2013-5851: Improve stream factories

  - S8013506: Better Pack200 data handling

  - S8013510, CVE-2013-5809: Augment image writing code

  - S8013514: Improve stability of cmap class

  - S8013739, CVE-2013-5817: Better LDAP resource management

  - S8013744, CVE-2013-5783: Better tabling for AWT

  - S8014085: Better serialization support in JMX classes

  - S8014093, CVE-2013-5782: Improve parsing of images

  - S8014098: Better profile validation

  - S8014102, CVE-2013-5778: Improve image conversion

  - S8014341, CVE-2013-5803: Better service from Kerberos
    servers

  - S8014349, CVE-2013-5840: (cl) Class.getDeclaredClass
    problematic in some class loader configurations

  - S8014530, CVE-2013-5825: Better digital signature
    processing

  - S8014534: Better profiling support

  - S8014987, CVE-2013-5842: Augment serialization handling

  - S8015614: Update build settings

  - S8015731: Subject java.security.auth.subject to
    improvements

  - S8015743, CVE-2013-5774: Address internet addresses

  - S8016256: Make finalization final

  - S8016653, CVE-2013-5804: javadoc should ignore
    ignoreable characters in names

  - S8016675, CVE-2013-5797: Make Javadoc pages more robust

  - S8017196, CVE-2013-5850: Ensure Proxies are handled
    appropriately

  - S8017287, CVE-2013-5829: Better resource disposal

  - S8017291, CVE-2013-5830: Cast Proxies Aside

  - S8017298, CVE-2013-4002: Better XML support

  - S8017300, CVE-2013-5784: Improve Interface
    Implementation

  - S8017505, CVE-2013-5820: Better Client Service

  - S8019292: Better Attribute Value Exceptions

  - S8019617: Better view of objects

  - S8020293: JVM crash

  - S8021275, CVE-2013-5805: Better screening for ScreenMenu

  - S8021282, CVE-2013-5806: Better recycling of object
    instances

  - S8021286: Improve MacOS resourcing

  - S8021290, CVE-2013-5823: Better signature validation

  - S8022931, CVE-2013-5800: Enhance Kerberos exceptions

  - S8022940: Enhance CORBA translations

  - S8023683: Enhance class file parsing

  - Backports

  - S6614237: missing codepage Cp290 at java runtime

  - S8005932: Java 7 on mac os x only provides text
    clipboard formats

  - S8014046: (process) Runtime.exec(String) fails if
    command contains spaces [win]

  - S8015144: Performance regression in ICU OpenType Layout
    library

  - S8015965: (process) Typo in name of property to allow
    ambiguous commands

  - S8015978: Incorrect transformation of XPath expression
    'string(-0)'

  - S8016357: Update hotspot diagnostic class

  - S8019584:
    javax/management/remote/mandatory/loading/MissingClassTe
    st.java failed in nightly against jdk7u45:
    java.io.InvalidObjectException: Invalid notification:
    null

  - S8019969:
    nioNetworkChannelInet6/SetOptionGetOptionTestInet6 test
    case crashes

  - S8020032: 7u fastdebug doesn't generate fastdebuginfo
    file

  - S8020085: Linux ARM build failure for 7u45

  - S8020088: Increment minor version of HSx for 7u45 and
    initialize the build number

  - S8020551: increment hsx build to b03 for 7u45-b03

  - S8020943: Memory leak when GCNotifier uses
    create_from_platform_dependent_str()

  - S8021287: Improve MacOS resourcing

  - S8021355: REGRESSION: Five closed/java/awt/SplashScreen
    tests fail since 7u45 b01 on Linux, Solaris

  - S8021360: object not exported' on start of
    JMXConnectorServer for RMI-IIOP protocol with security
    manager

  - S8021366:
    java_util/Properties/PropertiesWithOtherEncodings fails
    during 7u45 nightly testing

  - S8021577: JCK test
    api/javax_management/jmx_serial/modelmbean/ModelMBeanNot
    ificationInfo/serial/index.html#Input has failed since
    jdk 7u45 b01

  - S8021899: Re-adjust fix of # 8020498 in 7u45 after
    mergeing 7u40

  - S8021901: Increment hsx build to b05 for 7u45-b05

  - S8021933: Add extra check for fix # JDK-8014530

  - S8021969: The index_AccessAllowed jnlp can not load
    successfully with exception thrown in the log.

  - S8022066: Evaluation of method reference to signature
    polymorphic method crashes VM

  - S8022086: Fixing licence of newly added files

  - S8022254: Remove incorrect jdk7u45-b05 tag from
    jdk7u-cpu forest

  - S8022661: InetAddress.writeObject() performs flush() on
    object output stream

  - S8022682: Supporting XOM

  - S8022808: Kitchensink hangs on macos

  - S8022856: 7u45 l10n resource file translation update

  - S8023323: Increment hsx build to b06 for 7u45-b08

  - S8023457: Event based tracing framework needs a mutex
    for thread groups

  - S8023478: Test fails with HS crash in GCNotifier.

  - S8023741: Increment hsx 24.45 build to b07 for 7u45-b09

  - S8023771: when USER_RELEASE_SUFFIX is set in order to
    add a string to java -version, build number in the
    bundles names should not be changed to b00

  - S8023888: Increment hsx 24.45 build to b08 for 7u45-b10

  - S8023964: java/io/IOException/LastErrorString.java
    should be @ignore-d

  - S8024369: Increment build # of hs24.0 to b57 for
    7u40-b61 psu

  - S8024668:
    api/java_nio/charset/Charset/index.html#Methods
    JCK-runtime test fails with 7u45 b11

  - S8024697: Fix for 8020983 causes Xcheck:jni warnings

  - S8024863: X11: Support GNOME Shell as mutter

  - S8024883: (se) SelectableChannel.register throws NPE if
    fd >= 64k (lnx)

  - S8025128: File.createTempFile fails if prefix is
    absolute path

  - S8025170: jdk7u51 7u-1-prebuild is failing since 9/19

  - Bug fixes

  - PR1400: Menu of maximized AWT window not working in Mate

  - Update to icedtea 2.4.2 

  - System LCMS 2 support again enabled by default,
    requiring 2.5 or above.

  - OpenJDK

  - S7122222: GC log is limited to 2G for 32-bit

  - S7162400: Intermittent java.io.IOException: Bad file
    number during HotSpotVirtualMachine.executeCommand

  - S7165807: Non optimized initialization of NSS crypto
    library leads to scalability issues

  - S7199324: IPv6: JMXConnectorServer.getConnectionIDs()
    return IDs contradicting to address grammar

  - S8001345: VM crashes with assert(n->outcnt() != 0 ||
    C->top() == n || n->is_Proj()) failed: No dead
    instructions after post-alloc

  - S8001424: G1: Rename certain G1-specific flags

  - S8001425: G1: Change the default values for certain G1
    specific flags

  - S8004859: Graphics.getClipBounds/getClip return
    difference nonequivalent bounds, depending from
    transform

  - S8005019: JTable passes row index instead of length when
    inserts selection interval

  - S8005194: [parfait] #353
    sun/awt/image/jpeg/imageioJPEG.c Memory leak of pointer
    'scale' allocated with calloc()

  - S8006941: [macosx] Deadlock in drag and drop

  - S8007898: Incorrect optimization of Memory Barriers in
    Matcher::post_store_load_barrier()

  - S8009168: accessibility.properties syntax issue

  - S8009985: [parfait] Uninitialised variable at
    jdk/src/solaris/native/com/sun/management/UnixOperatingS
    ystem_md.c

  - S8011064: Some tests have failed with SIGSEGV on
    arm-hflt on build b82

  - S8011569: ARM -- avoid native stack walking

  - S8011760: assert(delta != 0) failed: dup pointer in
    MemBaseline::malloc_sort_by_addr

  - S8012144: multiple SIGSEGVs fails on staxf

  - S8012156: tools/javac/file/zip/T6865530.java fails for
    win32/64

  - S8012241: NMT huge memory footprint, it usually leads to
    OOME

  - S8012366: Fix for 8007815 breaks down when only building
    OpenJDK (without deploy and install forests)

  - S8013546: compiler/8011901/Test8011901.java fails with
    CompilationError: Compilation failed

  - S8013719: Increment build # of hs23.21 to b02

  - S8013791: G1: G1CollectorPolicy::initialize_flags() may
    set min_alignment > max_alignment

  - S8014264: The applet pathguy_TimeDead throws
    java.lang.NullPointerException in java console once
    click drop-down check box.

  - S8014312: Fork hs23.25 hsx from hs23.21 for jdk7u25 and
    reinitialize build number

  - S8014805: NPE is thrown during certpath validation if
    certificate does not have AuthorityKeyIdentifier
    extension

  - S8014850: Third-Party License Readme updates for 7u40

  - S8014925: Disable
    sun.reflect.Reflection.getCallerClass(int) with a
    temporary switch to re-enable it

  - S8015237: Parallelize string table scanning during
    strong root processing

  - S8015411: Bump the hsx build number for 7u21-b50 for
    customer

  - S8015441: runThese crashed with assert(opcode == Op_ConP
    || opcode == Op_ThreadLocal || opcode == Op_CastX2P ..)
    failed: sanity

  - S8015576: CMS: svc agent throws
    java.lang.RuntimeException: No type named 'FreeList' in
    database

  - S8015668: overload resolution: performance regression in
    JDK 7

  - S8015884: runThese crashed with SIGSEGV, hs_err has an
    error instead of stacktrace

  - S8016074: NMT: assertion failed:
    assert(thread->thread_state() == from) failed: coming
    from wrong thread state

  - S8016102: Increment build # of hs23.25 to b02 for
    7u25-b31 psu

  - S8016131: nsk/sysdict/vm/stress/chain tests crash the VM
    in 'entry_frame_is_first()'

  - S8016133: Regression: diff. behavior with user-defined
    SAXParser

  - S8016157: During CTW: C2:
    assert(!def_outside->member(r)) failed: Use of external
    LRG overlaps the same LRG defined in this block

  - S8016331: Minor issues in event tracing metadata

  - S8016648: FEATURE_SECURE_PROCESSING set to true or false
    causes SAXParseException to be thrown

  - S8016734: Remove extra code due to duplicated push

  - S8016737: After clicking on 'Print UNCOLLATED' button,
    the print out come in order 'Page 1', 'Page 2', 'Page 1'

  - S8016740: assert in GC_locker from PSOldGen::expand with
    -XX:+PrintGCDetails and Verbose

  - S8016767: Provide man pages generated from DARB for
    OpenJDK

  - S8017070: G1: assert(_card_counts[card_num] <=
    G1ConcRSHotCardLimit) failed

  - S8017159: Unexclude sun/tools/JMAP/Basic.sh test

  - S8017173: XMLCipher with RSA_OAEP Key Transport
    algorithm can't be instantiated

  - S8017174: NPE when using Logger.getAnonymousLogger or
    LogManager.getLogManager().getLogger

  - S8017189: [macosx] AWT program menu disabled on Mac

  - S8017252: new hotspot build - hs24-b51

  - S8017478: Kitchensink crashed with SIGSEGV in
    BaselineReporter::diff_callsites

  - S8017483: G1 tests fail with native OOME on Solaris x86
    after HeapBaseMinAddress has been increased

  - S8017510: Add a regression test for 8005956

  - S8017566: Backout 8000450 - Cannot access to
    com.sun.corba.se.impl.orb.ORBImpl

  - S8017588: SA: jstack -l throws UnalignedAddressException
    while attaching to core file for java that was started
    with CMS GC

  - S8019155: Update makefiles with correct jfr packages

  - S8019201: Regression: java.awt.image.ConvolveOp throws
    java.awt.image.ImagingOpException

  - S8019236: [macosx] Add javadoc to the
    handleWindowFocusEvent in CEmbeddedFrame

  - S8019265: [macosx] apple.laf.useScreenMenuBar regression
    comparing with jdk6

  - S8019298: new hotspot build - hs24-b52

  - S8019381: HashMap.isEmpty is non-final, potential issues
    for get/remove

  - S8019541: 7u40 l10n resource file translation update

  - S8019587: [macosx] Possibility to set the same frame for
    the different screens

  - S8019625: Test compiler/8005956/PolynomialRoot.java
    timeouts on Solaris SPARCs

  - S8019628: [macosx]
    closed/java/awt/Modal/BlockedMouseInputTest/BlockedMouse
    InputTest.html failed since 7u40b30 on MacOS

  - S8019826: Test
    com/sun/management/HotSpotDiagnosticMXBean/SetVMOption.j
    ava fails with NPE

  - S8019933: new hotspot build - hs24-b53

  - S8019979: Replace CheckPackageAccess test with better
    one from closed repo

  - S8020038: [macosx] Incorrect usage of invokeLater() and
    likes in callbacks called via JNI from AppKit thread

  - S8020054: (tz) Support tzdata2013d

  - S8020155: PSR:PERF G1 not collecting old regions when
    humongous allocations interfer

  - S8020215: Different execution plan when using JIT vs
    interpreter

  - S8020228: Restore the translated version of
    logging_xx.properties

  - S8020298: [macosx] Incorrect merge in the lwawt code

  - S8020319: Update Japanese man pages for 7u40

  - S8020371: [macosx] applets with Drag and Drop fail with
    IllegalArgumentException

  - S8020381: new hotspot build - hs24-b54

  - S8020425: Product options incorrectly removed in minor
    version

  - S8020430: NullPointerException in xml sqe nightly result
    on 2013-07-12

  - S8020433: Crash when using -XX:+RestoreMXCSROnJNICalls

  - S8020498: Crash when both libnet.so and libmawt.so are
    loaded

  - S8020525: Increment build # of hs23.25 to b03 for
    7u25-b34 psu

  - S8020547: Event based tracing needs a UNICODE string
    type

  - S8020625: [TESTBUG]
    java/util/HashMap/OverrideIsEmpty.java doesn't compile
    for jdk7u

  - S8020701: Avoid crashes in WatcherThread

  - S8020796: new hotspot build - hs24-b55

  - S8020811: [macosx] Merge fault 7u25-7u40: Missed focus
    fix JDK-8012330

  - S8020940: Valid OCSP responses are rejected for
    backdated enquiries

  - S8020983: OutOfMemoryError caused by non garbage
    collected JPEGImageWriter Instances

  - S8021008: Provide java and jcmd man pages for Mac
    (OpenJDK)

  - S8021148: Regression in SAXParserImpl in 7u40 b34 (NPE)

  - S8021353: Event based tracing is missing thread exit

  - S8021381: JavaFX scene included in Swing JDialog not
    starting from Web Start

  - S8021565: new hotspot build - hs24-b56

  - S8021771: warning stat64 is deprecated - when building
    on OSX 10.7.5

  - S8021946: Disabling
    sun.reflect.Reflection.getCallerCaller(int) by default
    breaks several frameworks and libraries

  - S8022548: SPECJVM2008 has errors introduced in 7u40-b34

  - S8023751: Need to backout 8020943, was pushed to hs24
    without approval

  - S8024914: Swapped usage of idx_t and bm_word_t types in
    bitMap.inline.hpp

  - New features

  - RH991170: java does not use correct kerberos credential
    cache

  - PR1536: Allow use of system Kerberos to obtain cache
    location

  - PR1551: Add build support for Zero AArch64

  - PR1552: Add -D_LITTLE_ENDIAN for ARM architectures.

  - PR1553: Add Debian AArch64 support

  - PR1554: Fix build on Mac OS X

  - Bug fixes

  - RH661505: JPEGs with sRGB IEC61966-2.1 color profiles
    have wrong colors

  - RH995488: Java thinks that the default timezone is
    Busingen instead of Zurich

  - Cleanup file resources properly in TimeZone_md.

  - PR1410: Icedtea 2.3.9 fails to build using icedtea
    1.12.4

  - G477456: emerge fails on pax system: java attempts RWX
    map, paxctl -m missing

  - G478484: patches/boot/ecj-diamond.patch FAILED

  - Fix Zero following changes to entry_frame_call_wrapper
    in 8016131

  - Set ZERO_BUILD in flags.make so it is set on rebuilds

  - Cast should use same type as GCDrainStackTargetSize
    (uintx).

  - Add casts to fix build on S390

  - JamVM

  - JSR292: Invoke Dynamic

  - sun.misc.Unsafe: additional methods get/putAddress:
    allows JamVM with OpenJDK 7/8 to run recent versions of
    JEdit.

  - FreeClassData: adjust method count for Miranda methods

  - Patches changes (mostly sync with Fedora)

  - removed java-1.7.0-openjdk-arm-fixes.patch, fixed
    upstream

  - removed java-1.7.0-openjdk-fork.patch, fixed upstream

  - renamed java-1.7.0-openjdk-bitmap.patch to
    zero-s8024914.patch

  - renamed java-1.7.0-openjdk-size_t.patch to
    zero-size_t.patch

  - added PStack-808293.patch

  - added RH661505-toBeReverted.patch

  - added abrt_friendly_hs_log_jdk7.patch

  - added gstackbounds.patch

  - added java-1.7.0-openjdk-freetype-check-fix.patch

  - added pulse-soundproperties.patch

  - added rhino.patch

  - added zero-entry_frame_call_wrapper.patch

  - added zero-gcdrainstacktargetsize.patch

  - added zero-zero_build.patch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-11/msg00023.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=846999"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_7_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-1.7.0.6-3.48.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.6-3.48.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-debugsource-1.7.0.6-3.48.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-demo-1.7.0.6-3.48.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.6-3.48.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-devel-1.7.0.6-3.48.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.6-3.48.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-javadoc-1.7.0.6-3.48.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-src-1.7.0.6-3.48.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-1.7.0.6-8.24.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.6-8.24.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-debugsource-1.7.0.6-8.24.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-demo-1.7.0.6-8.24.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.6-8.24.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-devel-1.7.0.6-8.24.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.6-8.24.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-javadoc-1.7.0.6-8.24.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-src-1.7.0.6-8.24.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_0-openjdk / java-1_7_0-openjdk-debuginfo / etc");
}
