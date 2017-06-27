#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1380.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95532);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/05 14:32:01 $");

  script_cve_id("CVE-2016-5542", "CVE-2016-5554", "CVE-2016-5556", "CVE-2016-5568", "CVE-2016-5573", "CVE-2016-5582", "CVE-2016-5597");

  script_name(english:"openSUSE Security Update : java-1_8_0-openjdk (openSUSE-2016-1380)");
  script_summary(english:"Check for the openSUSE-2016-1380 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenJDK Java was updated to jdk8u111 (icedtea 3.2.0) to fix the
following issues :

  - Security fixes

  + S8146490: Direct indirect CRL checks

  + S8151921: Improved page resolution

  + S8155968: Update command line options

  + S8155973, CVE-2016-5542: Tighten jar checks
    (bsc#1005522)

  + S8156794: Extend data sharing

  + S8157176: Improved classfile parsing

  + S8157739, CVE-2016-5554: Classloader Consistency
    Checking (bsc#1005523)

  + S8157749: Improve handling of DNS error replies

  + S8157753: Audio replay enhancement

  + S8157759: LCMS Transform Sampling Enhancement

  + S8157764: Better handling of interpolation plugins

  + S8158302: Handle contextual glyph substitutions

  + S8158993, CVE-2016-5568: Service Menu services
    (bsc#1005525)

  + S8159495: Fix index offsets

  + S8159503: Amend Annotation Actions

  + S8159511: Stack map validation

  + S8159515: Improve indy validation

  + S8159519, CVE-2016-5573: Reformat JDWP messages
    (bsc#1005526)

  + S8160090: Better signature handling in pack200

  + S8160094: Improve pack200 layout

  + S8160098: Clean up color profiles

  + S8160591, CVE-2016-5582: Improve internal array handling
    (bsc#1005527)

  + S8160838, CVE-2016-5597: Better HTTP service
    (bsc#1005528)

  + PR3206, RH1367357: lcms2: Out-of-bounds read in
    Type_MLU_Read()

  + CVE-2016-5556 (bsc#1005524)

  - New features

  + PR1370: Provide option to build without debugging

  + PR1375: Provide option to strip and link debugging info
    after build

  + PR1537: Handle alternative Kerberos credential cache
    locations

  + PR1978: Allow use of system PCSC

  + PR2445: Support system libsctp

  + PR3182: Support building without pre-compiled headers

  + PR3183: Support Fedora/RHEL system crypto policy

  + PR3221: Use pkgconfig to detect Kerberos CFLAGS and
    libraries

  - Import of OpenJDK 8 u102 build 14

  + S4515292: ReferenceType.isStatic() returns true for
    arrays

  + S4858370: JDWP: Memory Leak: GlobalRefs never deleted
    when processing invokeMethod command

  + S6976636: JVM/TI test ex03t001 fails assertion

  + S7185591: jcmd-big-script.sh ERROR: could not find app's
    Java pid.

  + S8017462: G1: guarantee fails with
    UseDynamicNumberOfGCThreads

  + S8034168: ThreadMXBean/Locks.java failed, blocked on
    wrong object

  + S8036006: [TESTBUG]
    sun/tools/native2ascii/NativeErrors.java fails: Process
    exit code was 0, but error was expected.

  + S8041781: Need new regression tests for PBE keys

  + S8041787: Need new regressions tests for buffer handling
    for PBE algorithms

  + S8043836: Need new tests for AES cipher

  + S8044199: Tests for RSA keys and key specifications

  + S8044772: TempDirTest.java still times out with -Xcomp

  + S8046339: sun.rmi.transport.DGCAckHandler leaks memory

  + S8047031: Add SocketPermission tests for legacy socket
    types

  + S8048052: Permission tests for setFactory

  + S8048138: Tests for JAAS callbacks

  + S8048147: Privilege tests with JAAS Subject.doAs

  + S8048356: SecureRandom default provider tests

  + S8048357: PKCS basic tests

  + S8048360: Test signed jar files

  + S8048362: Tests for doPrivileged with accomplice

  + S8048596: Tests for AEAD ciphers

  + S8048599: Tests for key wrap and unwrap operations

  + S8048603: Additional tests for MAC algorithms

  + S8048604: Tests for strong crypto ciphers

  + S8048607: Test key generation of DES and DESEDE

  + S8048610: Implement regression test for bug fix of
    4686632 in JCE

  + S8048617: Tests for PKCS12 read operations

  + S8048618: Tests for PKCS12 write operations.

  + S8048619: Implement tests for converting PKCS12
    keystores

  + S8048624: Tests for SealedObject

  + S8048819: Implement reliability test for DH algorithm

  + S8048820: Implement tests for SecretKeyFactory

  + S8048830: Implement tests for new functionality provided
    in JEP 166

  + S8049237: Need new tests for X509V3 certificates

  + S8049321: Support SHA256WithDSA in JSSE

  + S8049429: Tests for java client server communications
    with various TLS/SSL combinations.

  + S8049432: New tests for TLS property
    jdk.tls.client.protocols

  + S8049814: Additional SASL client-server tests

  + S8050281: New permission tests for JEP 140

  + S8050370: Need new regressions tests for messageDigest
    with DigestIOStream

  + S8050371: More MessageDigest tests

  + S8050374: More Signature tests

  + S8050427: LoginContext tests to cover JDK-4703361

  + S8050460: JAAS login/logout tests with LoginContext

  + S8050461: Tests for syntax checking of JAAS
    configuration file

  + S8054278: Refactor jps utility tests

  + S8055530: assert(_exits.control()->is_top() ||
    !_gvn.type(ret_phi)->empty()) failed: return value must
    be well defined

  + S8055844: [TESTBUG]
    test/runtime/NMT/VirtualAllocCommitUncommitRecommit.java
    fails on Solaris Sparc due to incorrect page size being
    used

  + S8059677: Thread.getName() instantiates Strings

  + S8061464: A typo in CipherTestUtils test

  + S8062536: [TESTBUG] Conflicting GC combinations in jdk
    tests

  + S8065076:
    java/net/SocketPermission/SocketPermissionTest.java
    fails intermittently

  + S8065078: NetworkInterface.getNetworkInterfaces()
    triggers intermittent test failures

  + S8066871: java.lang.VerifyError: Bad local variable type
    - local final String

  + S8068427: Hashtable deserialization reconstitutes table
    with wrong capacity

  + S8069038: javax/net/ssl/TLS/TLSClientPropertyTest.java
    needs to be updated for JDK-8061210

  + S8069253: javax/net/ssl/TLS/TestJSSE.java failed on Mac

  + S8071125: Improve exception messages in URLPermission

  + S8072081: Supplementary characters are rejected in
    comments

  + S8072463: Remove requirement that AKID and SKID have to
    match when building certificate chain

  + S8072725: Provide more granular levels for GC
    verification

  + S8073400: Some Monospaced logical fonts have a different
    width

  + S8073872: Schemagen fails with StackOverflowError if
    element references containing class

  + S8074931: Additional tests for CertPath API

  + S8075286: Additional tests for signature algorithm OIDs
    and transformation string

  + S8076486: [TESTBUG]
    javax/security/auth/Subject/doAs/NestedActions.java
    fails if extra VM options are given

  + S8076545: Text size is twice bigger under Windows L&F on
    Win 8.1 with HiDPI display

  + S8076995:
    gc/ergonomics/TestDynamicNumberOfGCThreads.java failed
    with java.lang.RuntimeException: 'new_active_workers'
    missing from stdout/stderr

  + S8079138: Additional negative tests for XML signature
    processing

  + S8081512: Remove sun.invoke.anon classes, or move /
    co-locate them with tests

  + S8081771: ProcessTool.createJavaProcessBuilder() needs
    new addTestVmAndJavaOptions argument

  + S8129419: heapDumper.cpp: assert(length_in_bytes > 0)
    failed: nothing to copy

  + S8130150: Implement BigInteger.montgomeryMultiply
    intrinsic

  + S8130242: DataFlavorComparator transitivity exception

  + S8130304: Inference: NodeNotFoundException thrown with
    deep generic method call chain

  + S8130425: libjvm crash due to stack overflow in
    executables with 32k tbss/tdata

  + S8133023: ParallelGCThreads is not calculated correctly

  + S8134111: Unmarshaller unmarshalls XML element which
    doesn't have the expected namespace

  + S8135259: InetAddress.getAllByName only reports 'unknown
    error' instead of actual cause

  + S8136506: Include sun.arch.data.model as a property that
    can be queried by jtreg

  + S8137068: Tests added in JDK-8048604 fail to compile

  + S8139040: Fix initializations before
    ShouldNotReachHere() etc. and enable -Wuninitialized on
    linux.

  + S8139581: AWT components are not drawn after removal and
    addition to a container

  + S8141243: Unexpected timezone returned after parsing a
    date

  + S8141420: Compiler runtime entries don't hold Klass*
    from being GCed

  + S8141445: Use of Solaris/SPARC M7 libadimalloc.so can
    generate unknown signal in hs_err file

  + S8141551: C2 can not handle returns with inccompatible
    interface arrays

  + S8143377: Test PKCS8Test.java fails

  + S8143647: Javac compiles method reference that allows
    results in an IllegalAccessError

  + S8144144: ORB destroy() leaks filedescriptors after
    unsuccessful connection

  + S8144593: Suppress not recognized property/feature
    warning messages from SAXParser

  + S8144957: Remove PICL warning message

  + S8145039: JAXB marshaller fails with ClassCastException
    on classes generated by xjc

  + S8145228: Java Access Bridge,
    getAccessibleStatesStringFromContext doesn't wrap the
    call to getAccessibleRole

  + S8145388: URLConnection.guessContentTypeFromStream
    returns image/jpg for some JPEG images

  + S8145974: XMLStreamWriter produces invalid XML for
    surrogate pairs on OutputStreamWriter

  + S8146035: Windows - With LCD antialiasing, some glyphs
    are not rendered correctly

  + S8146192: Add test for JDK-8049321

  + S8146274: Thread spinning on WeakHashMap.getEntry() with
    concurrent use of nashorn

  + S8147468: Allow users to bound the size of buffers
    cached in the per-thread buffer caches

  + S8147645: get_ctrl_no_update() code is wrong

  + S8147807: crash in libkcms.so on linux-sparc

  + S8148379: jdk.nashorn.api.scripting spec. adjustments,
    clarifications

  + S8148627: RestrictTestMaxCachedBufferSize.java to 64-bit
    platforms

  + S8148820: Missing @since Javadoc tag in
    Logger.log(Level, Supplier)

  + S8148926: Call site profiling fails on braces-wrapped
    anonymous function

  + S8149017: Delayed provider selection broken in RSA
    client key exchange

  + S8149029: Secure validation of XML based digital
    signature always enabled when checking wrapping attacks

  + S8149330: Capacity of StringBuilder should not get close
    to Integer.MAX_VALUE unless necessary

  + S8149334: JSON.parse(JSON.stringify([])).push(10)
    creates an array containing two elements

  + S8149368: [hidpi] JLabel font is twice bigger than
    JTextArea font on Windows 7,HiDPI, Windows L&F

  + S8149411: PKCS12KeyStore cannot extract AES Secret Keys

  + S8149417: Use final restricted flag

  + S8149450: LdapCtx.processReturnCode() throwing NULL
    pointer Exception

  + S8149453: [hidpi] JFileChooser does not scale properly
    on Windows with HiDPI display and Windows L&F

  + S8149543: range check CastII nodes should not be split
    through Phi

  + S8149743: JVM crash after debugger hotswap with lambdas

  + S8149744: fix testng.jar delivery in Nashorn build.xml

  + S8149915: enabling validate-annotations feature for xsd
    schema with annotation causes NPE

  + S8150002: Check for the validity of oop before printing
    it in verify_remembered_set

  + S8150470: JCK: api/xsl/conf/copy/copy19 test failure

  + S8150518: G1 GC crashes at
    G1CollectedHeap::do_collection_pause_at_safepoint(double
    )

  + S8150533: Test
    java/util/logging/LogManagerAppContextDeadlock.java
    times out intermittently.

  + S8150704: XALAN: ERROR: 'No more DTM IDs are available'
    when transforming with lots of temporary result trees

  + S8150780: Repeated offer and remove on
    ConcurrentLinkedQueue lead to an OutOfMemoryError

  + S8151064: com/sun/jdi/RedefineAddPrivateMethod.sh fails
    intermittently

  + S8151197: [TEST_BUG] Need to backport fix for
    test/javax/net/ssl/TLS/TestJSSE.java

  + S8151352: jdk/test/sample fails with 'effective library
    path is outside the test suite'

  + S8151431: DateFormatSymbols triggers this.clone() in the
    constructor

  + S8151535: TESTBUG:
    java/lang/invoke/AccessControlTest.java should be
    modified to run with JTREG 4.1 b13

  + S8151731: Add new jtreg keywords to jdk 8

  + S8151998: VS2010 ThemeReader.cpp(758) : error C3861:
    'round': identifier not found

  + S8152927: Incorrect GPL header in
    StubFactoryDynamicBase.java reported

  + S8153252: SA: Hotspot build on Windows fails if
    make/closed folder does not exist

  + S8153531: Improve exception messaging for
    RSAClientKeyExchange

  + S8153641: assert(thread_state == _thread_in_native)
    failed: Assumed thread_in_native while heap dump

  + S8153673: [BACKOUT] JDWP: Memory Leak: GlobalRefs never
    deleted when processing invokeMethod command

  + S8154304: NullpointerException at
    LdapReferralException.getReferralContext

  + S8154722: Test
    gc/ergonomics/TestDynamicNumberOfGCThreads.java fails

  + S8157078: 8u102 L10n resource file updates

  + S8157838: Personalized Windows Font Size is not taken
    into account in Java8u102

  - Import of OpenJDK 8 u111 build 14

  + S6882559: new JEditorPane('text/plain','') fails for
    null context class loader

  + S8049171: Additional tests for jarsigner's warnings

  + S8063086: Math.pow yields different results upon
    repeated calls

  + S8140530: Creating a VolatileImage with size 0,0 results
    in no longer working g2d.drawString

  + S8142926: OutputAnalyzer's shouldXXX() calls return this

  + S8147077: IllegalArgumentException thrown by
    api/java_awt/Component/FlipBufferStrategy/indexTGF_Gener
    al

  + S8148127: IllegalArgumentException thrown by JCK test
    api/java_awt/Component/FlipBufferStrategy/indexTGF_Gener
    al in opengl pipeline

  + S8150611: Security problem on
    sun.misc.resources.Messages*

  + S8153399: Constrain AppCDS behavior (back port)

  + S8157653: [Parfait] Uninitialised variable in
    awt_Font.cpp

  + S8158734: JEditorPane.createEditorKitForContentType
    throws NPE after 6882559

  + S8158994: Service Menu services

  + S8159684: (tz) Support tzdata2016f

  + S8160904: Typo in code from 8079718 fix :
    enableCustomValueHanlde

  + S8160934: isnan() is not available on older MSVC
    compilers

  + S8161141: correct bugId for JDK-8158994 fix push

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

  + S8078628, PR3208: Zero build fails with pre-compiled
    headers disabled

  + S8141491, PR3159, G592292: Unaligned memory access in
    Bits.c

  + S8157306, PR3121: Random infrequent NULL pointer
    exceptions in javac (enabled on AArch64 only)

  + S8162384, PR3122: Performance regression: bimorphic
    inlining may be bypassed by type speculation

  - Bug fixes

  + PR3123: Some object files built without -fPIC on x86
    only

  + PR3126: pax-mark-vm script calls 'exit -1' which is
    invalid in dash

  + PR3127, G590348: Only apply PaX markings by default on
    running PaX kernels

  + PR3199: Invalid nashorn URL

  + PR3201: Update infinality configure test

  + PR3218: PR3159 leads to build failure on clean tree

  - AArch64 port

  + S8131779, PR3220: AARCH64: add Montgomery multiply
    intrinsic

  + S8167200, PR3220: AArch64: Broken stack pointer
    adjustment in interpreter

  + S8167421, PR3220: AArch64: in one core system, fatal
    error: Illegal threadstate encountered

  + S8167595, PR3220: AArch64: SEGV in stub code
    cipherBlockChaining_decryptAESCrypt

  + S8168888, PR3220: Port 8160591: Improve internal array
    handling to AArch64.

  - Shenandoah

  + PR3224: Shenandoah broken when building without
    pre-compiled headers

  - Build against system kerberos 

  - Build against system pcsc and sctp 

  - S8158260, PR2991, RH1341258: PPC64: unaligned
    Unsafe.getInt can lead to the generation of illegal
    instructions (bsc#988651)

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
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
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988651"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_8_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-headless-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_8_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/05");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-1.8.0.111-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-accessibility-1.8.0.111-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.111-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-debugsource-1.8.0.111-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-demo-1.8.0.111-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.111-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-devel-1.8.0.111-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.111-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-headless-1.8.0.111-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.111-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-javadoc-1.8.0.111-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"java-1_8_0-openjdk-src-1.8.0.111-18.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-1.8.0.111-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-accessibility-1.8.0.111-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-debuginfo-1.8.0.111-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-debugsource-1.8.0.111-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-demo-1.8.0.111-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-demo-debuginfo-1.8.0.111-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-devel-1.8.0.111-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-devel-debuginfo-1.8.0.111-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-headless-1.8.0.111-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-headless-debuginfo-1.8.0.111-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-javadoc-1.8.0.111-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"java-1_8_0-openjdk-src-1.8.0.111-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_8_0-openjdk / java-1_8_0-openjdk-accessibility / etc");
}
