#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2012-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93281);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2016-3458", "CVE-2016-3485", "CVE-2016-3498", "CVE-2016-3500", "CVE-2016-3503", "CVE-2016-3508", "CVE-2016-3511", "CVE-2016-3550", "CVE-2016-3552", "CVE-2016-3587", "CVE-2016-3598", "CVE-2016-3606", "CVE-2016-3610");
  script_osvdb_id(141824, 141825, 141826, 141827, 141828, 141829, 141830, 141831, 141832, 141833, 141834, 141835, 141836);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : java-1_8_0-openjdk (SUSE-SU-2016:2012-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for java-1_8_0-openjdk fixes the following issues :

  - Upgrade to version jdk8u101 (icedtea 3.1.0)

  - New in release 3.1.0 (2016-07-25) :

  - Security fixes

  - S8079718, CVE-2016-3458: IIOP Input Stream Hooking
    (bsc#989732)

  - S8145446, CVE-2016-3485: Perfect pipe placement (Windows
    only) (bsc#989734)

  - S8146514: Enforce GCM limits

  - S8147771: Construction of static protection domains
    under Javax custom policy

  - S8148872, CVE-2016-3500: Complete name checking
    (bsc#989730)

  - S8149070: Enforce update ordering

  - S8149962, CVE-2016-3508: Better delineation of XML
    processing (bsc#989731)

  - S8150752: Share Class Data

  - S8151925: Font reference improvements

  - S8152479, CVE-2016-3550: Coded byte streams (bsc#989733)

  - S8153312: Constrain AppCDS behavior

  - S8154475, CVE-2016-3587: Clean up lookup visibility
    (bsc#989721)

  - S8155981, CVE-2016-3606: Bolster bytecode verification
    (bsc#989722)

  - S8155985, CVE-2016-3598: Persistent Parameter Processing
    (bsc#989723)

  - S8158571, CVE-2016-3610: Additional method handle
    validation (bsc#989725)

  - CVE-2016-3552 (bsc#989726)

  - CVE-2016-3511 (bsc#989727)

  - CVE-2016-3503 (bsc#989728)

  - CVE-2016-3498 (bsc#989729)

  - New features

  - S8145547, PR1061: [AWT/Swing] Conditional support for
    GTK 3 on Linux

  - PR2821: Support building OpenJDK with --disable-headful

  - PR2931, G478960: Provide Infinality Support via
    fontconfig

  - PR3079: Provide option to build Shenandoah on x86_64

  - Import of OpenJDK 8 u92 build 14

  - S6869327: Add new C2 flag to keep safepoints in counted
    loops.

  - S8022865: [TESTBUG] Compressed Oops testing needs to be
    revised

  - S8029630: Thread id should be displayed as a hex number
    in error report

  - S8029726: On OS X some dtrace probe names are mismatched
    with Solaris

  - S8029727: On OS X dtrace probes
    Call<type>MethodA/Call<type>MethodV are not fired.

  - S8029728: On OS X dtrace probes SetStaticBooleanField
    are not fired

  - S8038184: XMLSignature throws
    StringIndexOutOfBoundsException if ID attribute value is
    empty String

  - S8038349: Signing XML with DSA throws Exception when key
    is larger than 1024 bits

  - S8041501: ImageIO reader is not capable of reading JPEGs
    without JFIF header

  - S8041900: [macosx] Java forces the use of discrete GPU

  - S8044363: Remove special build options for unpack200
    executable

  - S8046471: Use OPENJDK_TARGET_CPU_ARCH instead of legacy
    value for hotspot ARCH

  - S8046611: Build errors with gcc on sparc/fastdebug

  - S8047763: Recognize sparc64 as a sparc platform

  - S8048232: Fix for 8046471 breaks PPC64 build

  - S8052396: Catch exceptions resulting from missing font
    cmap

  - S8058563: InstanceKlass::_dependencies list isn't
    cleared from empty nmethodBucket entries

  - S8061624: [TESTBUG] Some tests cannot be ran under
    compact profiles and therefore shall be excluded

  - S8062901: Iterators is spelled incorrectly in the
    Javadoc for Spliterator

  - S8064330: Remove SHA224 from the default support list if
    SunMSCAPI enabled

  - S8065579: WB method to start G1 concurrent mark cycle
    should be introduced

  - S8065986: Compiler fails to NullPointerException when
    calling super with Object()

  - S8066974: Compiler doesn't infer method's generic type
    information in lambda body

  - S8067800: Clarify java.time.chrono.Chronology.isLeapYear
    for out of range years

  - S8068033: JNI exception pending in
    jdk/src/share/bin/java.c

  - S8068042: Check
    jdk/src/share/native/sun/misc/URLClassPath.c for JNI
    pending

  - S8068162: jvmtiRedefineClasses.cpp: guarantee(false)
    failed: OLD and/or OBSOLETE method(s) found

  - S8068254: Method reference uses wrong qualifying type

  - S8074696: Remote debugging session hangs for several
    minutes when calling findBootType

  - S8074935: jdk8 keytool doesn't validate pem files for
    RFC 1421 correctness, as jdk7 did

  - S8078423: [TESTBUG]
    javax/print/PrintSEUmlauts/PrintSEUmlauts.java relies on
    system locale

  - S8080492: [Parfait] Uninitialised variable in
    jdk/src/java/desktop/windows/native/libawt/

  - S8080650: Enable stubs to use frame pointers correctly

  - S8122944: perfdata used is seen as too high on sparc
    zone with jdk1.9 and causes a test failure

  - S8129348: Debugger hangs in trace mode with TRACE_SENDS

  - S8129847: Compiling methods generated by Nashorn
    triggers high memory usage in C2

  - S8130506: javac AssertionError when invoking
    MethodHandle.invoke with lambda parameter

  - S8130910: hsperfdata file is created in wrong directory
    and not cleaned up if /tmp/hsperfdata_<username> has
    wrong permissions

  - S8131129: Attempt to define a duplicate BMH$Species
    class

  - S8131665: Bad exception message in
    HandshakeHash.getFinishedHash

  - S8131782: C1 Class.cast optimization breaks when Class
    is loaded from static final

  - S8132503: [macosx] Chinese full stop symbol cannot be
    entered with Pinyin IM on OS X

  - S8133207: ParallelProbes.java test fails after changes
    for JDK-8080115

  - S8133924: NPE may be thrown when xsltc select a
    non-existing node after JDK-8062518

  - S8134007: Improve string folding

  - S8134759: jdb: Incorrect stepping inside finally block

  - S8134963: [Newtest] New stress test for changing the
    coarseness level of G1 remembered set

  - S8136442: Don't tie Certificate signature algorithms to
    ciphersuites

  - S8137106: EUDC (End User Defined Characters) are not
    displayed on Windows with Java 8u60+

  - S8138745: Implement ExitOnOutOfMemory and
    CrashOnOutOfMemory in HotSpot

  - S8138764: In some cases the usage of TreeLock can be
    replaced by other synchronization

  - S8139373: [TEST_BUG]
    java/net/MulticastSocket/MultiDead.java failed with
    timeout

  - S8139424: SIGSEGV, Problematic frame: # V
    [libjvm.so+0xd0c0cc] void
    InstanceKlass::oop_oop_iterate_oop_maps_specialized<true
    ></true> shClosure>

  - S8139436: sun.security.mscapi.KeyStore might load
    incomplete data

  - S8139751: Javac crash with -XDallowStringFolding=false

  - S8139863: [TESTBUG] Need to port tests for JDK-8134903
    to 8u-dev

  - S8139985: JNI exception pending in
    jdk/src/jdk/hprof/agent/share/native/libhprof

  - S8140031: SA: Searching for a value in Threads does not
    work

  - S8140249: JVM Crashing During startUp If Flight
    Recording is enabled

  - S8140344: add support for 3 digit update release numbers

  - S8140587: Atomic*FieldUpdaters should use
    Class.isInstance instead of direct class check

  - S8141260: isReachable crash in windows xp

  - S8143297: Nashorn compilation time reported in
    nanoseconds

  - S8143397: It looks like InetAddress.isReachable(timeout)
    works incorrectly

  - S8143855: Bad printf formatting in frame_zero.cpp

  - S8143896: java.lang.Long is implicitly converted to
    double

  - S8143963: improve ClassLoader::trace_class_path to
    accept an additional outputStream* arg

  - S8144020: Remove long as an internal numeric type

  - S8144131: ArrayData.getInt implementations do not
    convert to int32

  - S8144483: One long Safepoint pause directly after each
    GC log rotation

  - S8144487: PhaseIdealLoop::build_and_optimize() must
    restore major_progress flag if skip_loop_opts is true

  - S8144885: agent/src/os/linux/libproc.h needs to support
    Linux/SPARC builds

  - S8144935: C2: safepoint is pruned from a non-counted
    loop

  - S8144937: [TEST_BUG] testlibrary_tests should be
    excluded for compact1 and compact2 execution

  - S8145017: Add support for 3 digit hotspot minor version
    numbers

  - S8145099: Better error message when SA can't attach to a
    process

  - S8145442: Add the facility to verify remembered sets for
    G1

  - S8145466: javac: No line numbers in compilation error

  - S8145539: (coll) AbstractMap.keySet and .values should
    not be volatile

  - S8145550: Megamorphic invoke should use CompiledFunction
    variants without any LinkLogic

  - S8145669: apply2call optimized callsite fails after
    becoming megamorphic

  - S8145722: NullPointerException in javadoc

  - S8145754: PhaseIdealLoop::is_scaled_iv_plus_offset()
    does not match AddI

  - S8146147: Java linker indexed property getter does not
    work for computed nashorn string

  - S8146566: OpenJDK build can't handle commas in LDFLAGS

  - S8146725: Issues with
    SignatureAndHashAlgorithm.getSupportedAlgorithms

  - S8146979: Backport of 8046471 breaks ppc64 build in
    jdk8u because 8072383 was badly backported before

  - S8147087: Race when reusing PerRegionTable bitmaps may
    result in dropped remembered set entries

  - S8147630: Wrong test result pushed to 8u-dev

  - S8147845: Varargs Array functions still leaking longs

  - S8147857: RMIConnector logs attribute names incorrectly

  - S8148353: [linux-sparc] Crash in libawt.so on Linux
    SPARC

  - S8150791: 8u76 L10n resource file translation update

  - Import of OpenJDK 8 u101 build 13

  - S6483657: MSCAPI provider does not create unique alias
    names

  - S6675699: need comprehensive fix for unconstrained
    ConvI2L with narrowed type

  - S8037557: test SessionCacheSizeTests.java timeout

  - S8038837: Add support to jarsigner for specifying
    timestamp hash algorithm

  - S8081778: Use Intel x64 CPU instructions for RSA
    acceleration

  - S8130150: Implement BigInteger.montgomeryMultiply
    intrinsic

  - S8130735: javax.swing.TimerQueue: timer fires late when
    another timer starts

  - S8143913: MSCAPI keystore should accept Certificate[] in
    setEntry()

  - S8144313: Test SessionTimeOutTests can be timeout

  - S8146240: Three nashorn files contain 'GNU General
    Public License' header

  - S8146387: Test SSLSession/SessionCacheSizeTests socket
    accept timed out

  - S8146669: Test SessionTimeOutTests fails intermittently

  - S8146993: Several javax/management/remote/mandatory
    regression tests fail after JDK-8138811

  - S8147994: [macosx] JScrollPane jitters up/down during
    trackpad scrolling on MacOS/Aqua

  - S8151522: Disable 8130150 and 8081778 intrinsics by
    default

  - S8151876: (tz) Support tzdata2016d

  - S8152098: Fix 8151522 caused test
    compiler/intrinsics/squaretolen/TestSquareToLen.java to
    fail

  - S8157077: 8u101 L10n resource file updates

  - Backports

  - S6260348, PR3066: GTK+ L&F JTextComponent not respecting
    desktop caret blink rate

  - S6778087, PR1061: getLocationOnScreen() always returns
    (0, 0) for mouse wheel events

  - S6961123, PR2972: setWMClass fails to null-terminate
    WM_CLASS string

  - S8008657, PR3077: JSpinner setComponentOrientation
    doesn't affect on text orientation

  - S8014212, PR2866: Robot captures black screen

  - S8029339, PR1061: Custom MultiResolution image support
    on HiDPI displays

  - S8031145, PR3077: Re-examine closed i18n tests to see it
    they can be moved to the jdk repository.

  - S8034856, PR3095: gcc warnings compiling
    src/solaris/native/sun/security/pkcs11

  - S8034857, PR3095: gcc warnings compiling
    src/solaris/native/sun/management

  - S8035054, PR3095: JarFacade.c should not include ctype.h

  - S8035287, PR3095: gcc warnings compiling various
    libraries files

  - S8038631, PR3077: Create wrapper for awt.Robot with
    additional functionality

  - S8039279, PR3077: Move awt tests to openjdk repository

  - S8041561, PR3077: Inconsistent opacity behaviour between
    JCheckBox and JRadioButton

  - S8041592, PR3077: [TEST_BUG] Move 42 AWT hw/lw mixing
    tests to jdk

  - S8041915, PR3077: Move 8 awt tests to OpenJDK regression
    tests tree

  - S8043126, PR3077: move awt automated functional tests
    from AWT_Events/Lw and AWT_Events/AWT to OpenJDK
    repository

  - S8043131, PR3077: Move ShapedAndTranslucentWindows and
    GC functional AWT tests to regression tree

  - S8044157, PR3077: [TEST_BUG] Improve recently submitted
    AWT_Mixing tests

  - S8044172, PR3077: [TEST_BUG] Move regtests for 4523758
    and AltPlusNumberKeyCombinationsTest to jdk

  - S8044429, PR3077: move awt automated tests for
    AWT_Modality to OpenJDK repository

  - S8044762, PR2960: com/sun/jdi/OptionTest.java test time
    out

  - S8044765, PR3077: Move functional tests
    AWT_SystemTray/Automated to openjdk repository

  - S8047180, PR3077: Move functional tests
    AWT_Headless/Automated to OpenJDK repository

  - S8047367, PR3077: move awt automated tests from
    AWT_Modality to OpenJDK repository - part 2

  - S8048246, PR3077: Move AWT_DnD/Clipboard/Automated
    functional tests to OpenJDK

  - S8049226, PR2960: com/sun/jdi/OptionTest.java test times
    out again

  - S8049617, PR3077: move awt automated tests from
    AWT_Modality to OpenJDK repository - part 3

  - S8049694, PR3077: Migrate functional
    AWT_DesktopProperties/Automated tests to OpenJDK

  - S8050885, PR3077: move awt automated tests from
    AWT_Modality to OpenJDK repository - part 4

  - S8051440, PR3077: move tests about maximizing
    undecorated to OpenJDK

  - S8052012, PR3077: move awt automated tests from
    AWT_Modality to OpenJDK repository - part 5

  - S8052408, PR3077: Move AWT_BAT functional tests to
    OpenJDK (3 of 3)

  - S8053657, PR3077: [TEST_BUG] move some 5 tests related
    to undecorated Frame/JFrame to JDK

  - S8054143, PR3077: move awt automated tests from
    AWT_Modality to OpenJDK repository - part 6

  - S8054358, PR3077: move awt automated tests from
    AWT_Modality to OpenJDK repository - part 7

  - S8054359, PR3077: move awt automated tests from
    AWT_Modality to OpenJDK repository - part 8

  - S8055360, PR3077: Move the rest part of AWT
    ShapedAndTranslucent tests to OpenJDK

  - S8055664, PR3077: move 14 tests about
    setLocationRelativeTo to jdk

  - S8055836, PR3077: move awt tests from AWT_Modality to
    OpenJDK repository - part 9

  - S8056911, PR3077: Remove internal API usage from
    ExtendedRobot class

  - S8057694, PR3077: move awt tests from AWT_Modality to
    OpenJDK repository - part 10

  - S8058959, PR1061:
    closed/java/awt/event/ComponentEvent/MovedResizedTwiceTe
    st/MovedResizedTwic eTest.java failed automatically

  - S8062606, PR3077: Fix a typo in java.awt.Robot class

  - S8063102, PR3077: Change open awt regression tests to
    avoid sun.awt.SunToolkit.realSync, part 1

  - S8063104, PR3077: Change open awt regression tests to
    avoid sun.awt.SunToolkit.realSync, part 2

  - S8063106, PR3077: Change open swing regression tests to
    avoid sun.awt.SunToolkit.realSync, part 1

  - S8063107, PR3077: Change open swing regression tests to
    avoid sun.awt.SunToolkit.realSync, part 2

  - S8064573, PR3077: [TEST_BUG]
    javax/swing/text/AbstractDocument/6968363/Test6968363.ja
    va is asocial pressing VK_LEFT and not releasing

  - S8064575, PR3077: [TEST_BUG]
    javax/swing/JEditorPane/6917744/bug6917744.java 100
    times press keys and never releases

  - S8064809, PR3077: [TEST_BUG]
    javax/swing/JComboBox/4199622/bug4199622.java contains a
    lot of keyPress and not a single keyRelease

  - S8067441, PR3077: Some tests fails with error: cannot
    find symbol getSystemMnemonicKeyCodes()

  - S8068228, PR3077: Test
    closed/java/awt/Mouse/MaximizedFrameTest/MaximizedFrameT
    est fails with GTKLookAndFeel

  - S8069361, PR1061: SunGraphics2D.getDefaultTransform()
    does not include scale factor

  - S8073320, PR1061: Windows HiDPI Graphics support

  - S8074807, PR3077: Fix some tests unnecessary using
    internal API

  - S8076315, PR3077: move 4 manual functional swing tests
    to regression suite

  - S8078504, PR3094: Zero lacks declaration of
    VM_Version::initialize()

  - S8129822, PR3077: Define 'headful' jtreg keyword

  - S8132123, PR1061: MultiResolutionCachedImage
    unnecessarily creates base image to get its size

  - S8133539, PR1061: [TEST_BUG] Split
    java/awt/image/MultiResolutionImageTest.java in two to
    allow restricted access

  - S8137571, PR1061: Linux HiDPI Graphics support

  - S8142406, PR1061: [TEST] MultiResolution image: need
    test to cover the case when @2x image is corrupted

  - S8145188, PR2945: No LocalVariableTable generated for
    the entire JDK

  - S8150258, PR1061: [TEST] HiDPI: create a test for
    multiresolution menu items icons

  - S8150724, PR1061: [TEST] HiDPI: create a test for
    multiresolution icons

  - S8150844, PR1061: [hidpi] [macosx] -Dsun.java2d.uiScale
    should be taken into account for OS X

  - S8151841, PR2882: Build needs additional flags to
    compile with GCC 6 [plus parts of 8149647 & 8032045]

  - S8155613, PR1061: [PIT] crash in
    AWT_Desktop/Automated/Exceptions/BasicTest

  - S8156020, PR1061: 8145547 breaks AIX and and uses
    RTLD_NOLOAD incorrectly

  - S8156128, PR1061: Tests for [AWT/Swing] Conditional
    support for GTK 3 on Linux

  - S8158260, PR2991, RH1341258: PPC64: unaligned
    Unsafe.getInt can lead to the generation of illegal
    instructions (bsc#988651)

  - S8159244, PR3074: Partially initialized string object
    created by C2's string concat optimization may escape

  - S8159690, PR3077: [TESTBUG] Mark headful tests with @key
    headful.

  - S8160294, PR2882, PR3095: Some client libraries cannot
    be built with GCC 6

  - Bug fixes

  - PR1958: GTKLookAndFeel does not honor
    gtk-alternative-button-order

  - PR2822: Feed LIBS & CFLAGS into configure rather than
    make to avoid re-discovery by OpenJDK configure

  - PR2932: Support ccache in a non-automagic manner

  - PR2933: Support ccache 3.2 and later

  - PR2964: Set system defaults based on OS

  - PR2974, RH1337583: PKCS#10 certificate requests now use
    CRLF line endings rather than system line endings

  - PR3078: Remove duplicated line dating back to 6788347
    and 6894807

  - PR3083, RH1346460: Regression in SSL debug output
    without an ECC provider

  - PR3089: Remove old memory limits patch

  - PR3090, RH1204159: SystemTap is heavily confused by
    multiple JDKs

  - PR3095: Fix warnings in URLClassPath.c

  - PR3096: Remove dead --disable-optimizations option

  - PR3105: Use version from hotspot.map to create tarball
    filename

  - PR3106: Handle both correctly-spelt property
    'enableCustomValueHandler' introduced by S8079718 and
    typo version

  - PR3108: Shenandoah patches not included in release
    tarball

  - PR3110: Update hotspot.map documentation in INSTALL

  - AArch64 port

  - S8145320, PR3078: Create unsafe_arraycopy and
    generic_arraycopy for AArch64

  - S8148328, PR3078: aarch64: redundant lsr instructions in
    stub code.

  - S8148783, PR3078: aarch64: SEGV running SpecJBB2013

  - S8148948, PR3078: aarch64: generate_copy_longs calls
    align() incorrectly

  - S8149080, PR3078: AArch64: Recognise disjoint array copy
    in stub code

  - S8149365, PR3078: aarch64: memory copy does not prefetch
    on backwards copy

  - S8149907, PR3078: aarch64: use load/store pair
    instructions in call_stub

  - S8150038, PR3078: aarch64: make use of CBZ and CBNZ when
    comparing narrow pointer with zero

  - S8150045, PR3078: arraycopy causes segfaults in SATB
    during garbage collection

  - S8150082, PR3078: aarch64: optimise small array copy

  - S8150229, PR3078: aarch64: pipeline class for several
    instructions is not set correctly

  - S8150313, PR3078: aarch64: optimise array copy using
    SIMD instructions

  - S8150394, PR3078: aarch64: add support for 8.1 LSE CAS
    instructions

  - S8151340, PR3078: aarch64: prefetch the destination word
    for write prior to ldxr/stxr loops.

  - S8151502, PR3078: optimize pd_disjoint_words and
    pd_conjoint_words

  - S8151775, PR3078: aarch64: add support for 8.1 LSE
    atomic operations

  - S8152537, PR3078: aarch64: Make use of CBZ and CBNZ when
    comparing unsigned values with zero.

  - S8152840, PR3078: aarch64: improve _unsafe_arraycopy
    stub routine

  - S8153713, PR3078: aarch64: improve short array clearing
    using store pair

  - S8153797, PR3078: aarch64: Add Arrays.fill stub code

  - S8154537, PR3078: AArch64: some integer rotate
    instructions are never emitted

  - S8154739, PR3078: AArch64: TemplateTable::fast_xaccess
    loads in wrong mode

  - S8155015, PR3078: Aarch64: bad assert in spill
    generation code

  - S8155100, PR3078: AArch64: Relax alignment requirement
    for byte_map_base

  - S8155612, PR3078: Aarch64: vector nodes need to support
    misaligned offset

  - S8155617, PR3078: aarch64: ClearArray does not use DC
    ZVA

  - S8155653, PR3078: TestVectorUnalignedOffset.java not
    pushed with 8155612

  - S8156731, PR3078: aarch64: java/util/Arrays/Correct.java
    fails due to _generic_arraycopy stub routine

  - S8157841, PR3078: aarch64: prefetch ignores cache line
    size

  - S8157906, PR3078: aarch64: some more integer rotate
    instructions are never emitted

  - S8158913, PR3078: aarch64: SEGV running Spark terasort

  - S8159052, PR3078: aarch64: optimise unaligned copies in
    pd_disjoint_words and pd_conjoint_words

  - S8159063, PR3078: aarch64: optimise unaligned array copy
    long

  - PR3078: Cleanup remaining differences from aarch64/jdk8u
    tree

  - Fix script linking /usr/share/javazi/tzdb.dat for
    platform where it applies (bsc#987895)

  - Fix aarch64 running with 48 bits va space (bsc#984684)
    avoid some crashes</username></type></type>

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989727"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989728"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3458.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3485.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3498.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3500.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3503.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3508.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3511.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3550.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3552.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3587.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3598.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3606.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3610.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162012-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85858211"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-SP1:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2016-1187=1

SUSE Linux Enterprise Desktop 12-SP1:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP1-2016-1187=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-1_8_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/02");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-1.8.0.101-14.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.101-14.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-debugsource-1.8.0.101-14.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-demo-1.8.0.101-14.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.101-14.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-devel-1.8.0.101-14.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-headless-1.8.0.101-14.3")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.101-14.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"java-1_8_0-openjdk-1.8.0.101-14.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.101-14.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"java-1_8_0-openjdk-debugsource-1.8.0.101-14.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"java-1_8_0-openjdk-headless-1.8.0.101-14.3")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.101-14.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_8_0-openjdk");
}
