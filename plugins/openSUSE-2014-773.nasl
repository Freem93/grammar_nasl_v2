#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-773.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80046);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/28 19:00:57 $");

  script_cve_id("CVE-2013-6629", "CVE-2013-6954", "CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0451", "CVE-2014-0452", "CVE-2014-0453", "CVE-2014-0454", "CVE-2014-0455", "CVE-2014-0456", "CVE-2014-0457", "CVE-2014-0458", "CVE-2014-0459", "CVE-2014-0460", "CVE-2014-0461", "CVE-2014-1876", "CVE-2014-2397", "CVE-2014-2398", "CVE-2014-2402", "CVE-2014-2403", "CVE-2014-2412", "CVE-2014-2413", "CVE-2014-2414", "CVE-2014-2421", "CVE-2014-2423", "CVE-2014-2427", "CVE-2014-2483", "CVE-2014-2490", "CVE-2014-4209", "CVE-2014-4216", "CVE-2014-4218", "CVE-2014-4219", "CVE-2014-4221", "CVE-2014-4223", "CVE-2014-4244", "CVE-2014-4252", "CVE-2014-4262", "CVE-2014-4263", "CVE-2014-4264", "CVE-2014-4266", "CVE-2014-4268");

  script_name(english:"openSUSE Security Update : java-1_7_0-openjdk (openSUSE-SU-2014:1638-1)");
  script_summary(english:"Check for the openSUSE-2014-773 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This openjdk update fixes the following security and non security
issues :

  - Upgrade to 2.4.8 (bnc#887530)

  - Changed back from gzipped tarball to xz

  - Changed the keyring file to add Andrew John Hughes that
    signed the icedtea package

  - Change ZERO to AARCH64 tarball

  - Removed patches :

  - gstackbounds.patch

  - java-1.7.0-openjdk-ppc-zero-jdk.patch

  - java-1.7.0-openjdk-ppc-zero-hotspot.patch

  - Integrated in upstream icedtea

  - java-1.7.0-openjdk-makefiles-zero.patch

  - Does not apply on the AARCH64 tarball, since the change
    from DEFAULT and ZERO tarball to DEFAULT and AARCH64

  - Upstream changes since 2.4.4 :

  - Security fixes

  - S8029755, CVE-2014-4209: Enhance subject class

  - S8030763: Validate global memory allocation

  - S8031340, CVE-2014-4264: Better TLS/EC management

  - S8031346, CVE-2014-4244: Enhance RSA key handling

  - S8031540: Introduce document horizon

  - S8032536: JVM resolves wrong method in some unusual
    cases

  - S8033055: Issues in 2d

  - S8033301, CVE-2014-4266: Build more informative
    InfoBuilder

  - S8034267: Probabilistic native crash

  - S8034272: Do not cram data into CRAM arrays

  - S8034985, CVE-2014-2483: Better form for Lambda Forms

  - S8035004, CVE-2014-4252: Provider provides less service

  - S8035009, CVE-2014-4218: Make Proxy representations
    consistent

  - S8035119, CVE-2014-4219: Fix exceptions to bytecode
    verification

  - S8035699, CVE-2014-4268: File choosers should be
    choosier

  - S8035788. CVE-2014-4221: Provide more consistency for
    lookups

  - S8035793, CVE-2014-4223: Maximum arity maxed out

  - S8036571: (process) Process process arguments carefully

  - S8036800: Attribute OOM to correct part of code

  - S8037046: Validate libraries to be loaded

  - S8037076, CVE-2014-2490: Check constant pool constants

  - S8037157: Verify <init> call

  - S8037162, CVE-2014-4263: More robust DH exchanges

  - S8037167, CVE-2014-4216: Better method signature
    resolution

  - S8039520, CVE-2014-4262: More atomicity of atomic
    updates

  - S8023046: Enhance splashscreen support

  - S8025005: Enhance CORBA initializations

  - S8025010, CVE-2014-2412: Enhance AWT contexts

  - S8025030, CVE-2014-2414: Enhance stream handling

  - S8025152, CVE-2014-0458: Enhance activation set up

  - S8026067: Enhance signed jar verification

  - S8026163, CVE-2014-2427: Enhance media provisioning

  - S8026188, CVE-2014-2423: Enhance envelope factory

  - S8026200: Enhance RowSet Factory

  - S8026716, CVE-2014-2402: (aio) Enhance asynchronous
    channel handling

  - S8026736, CVE-2014-2398: Enhance Javadoc pages

  - S8026797, CVE-2014-0451: Enhance data transfers

  - S8026801, CVE-2014-0452: Enhance endpoint addressing

  - S8027766, CVE-2014-0453: Enhance RSA processing

  - S8027775: Enhance ICU code.

  - S8027841, CVE-2014-0429: Enhance pixel manipulations

  - S8028385: Enhance RowSet Factory

  - S8029282, CVE-2014-2403: Enhance CharInfo set up

  - S8029286: Enhance subject delegation

  - S8029699: Update Poller demo

  - S8029730: Improve audio device additions

  - S8029735: Enhance service mgmt natives

  - S8029740, CVE-2014-0446: Enhance handling of loggers

  - S8029745, CVE-2014-0454: Enhance algorithm checking

  - S8029750: Enhance LCMS color processing (in-tree LCMS)

  - S8029760, CVE-2013-6629: Enhance AWT image libraries
    (in-tree libjpeg)

  - S8029844, CVE-2014-0455: Enhance argument validation

  - S8029854, CVE-2014-2421: Enhance JPEG decodings

  - S8029858, CVE-2014-0456: Enhance array copies

  - S8030731, CVE-2014-0460: Improve name service robustness

  - S8031330: Refactor ObjectFactory

  - S8031335, CVE-2014-0459: Better color profiling (in-tree
    LCMS)

  - S8031352, CVE-2013-6954: Enhance PNG handling (in-tree
    libpng)

  - S8031394, CVE-2014-0457: (sl) Fix exception handling in
    ServiceLoader

  - S8031395: Enhance LDAP processing

  - S8032686, CVE-2014-2413: Issues with method invoke

  - S8033618, CVE-2014-1876: Correct logging output

  - S8034926, CVE-2014-2397: Attribute classes properly

  - S8036794, CVE-2014-0461: Manage JavaScript instances

  - Backports

  - S5049299: (process) Use posix_spawn, not fork, on S10 to
    avoid swap exhaustion

  - S6571600: JNI use results in UnsatisfiedLinkError
    looking for libmawt.so

  - S7131153: GetDC called way too many times - causes bad
    performance.

  - S7190349: [macosx] Text (Label) is incorrectly drawn
    with a rotated g2d

  - S8001108: an attempt to use '<init>' as a method name
    should elicit NoSuchMethodException

  - S8001109: arity mismatch on a call to spreader method
    handle should elicit IllegalArgumentException

  - S8008118: (process) Possible NULL pointer dereference in
    jdk/src/solaris/native/java/lang/UNIXProcess_md.c

  - S8013611: Modal dialog fails to obtain keyboard focus

  - S8013809: deadlock in SSLSocketImpl between between
    write and close

  - S8013836: getFirstDayOfWeek reports wrong day for pt-BR
    locale

  - S8014460: Need to check for non-empty EXT_LIBS_PATH
    before using it

  - S8019853: Break logging and AWT circular dependency

  - S8019990: IM candidate window appears on the South-East
    corner of the display.

  - S8020191: System.getProperty('os.name') returns 'Windows
    NT (unknown)' on Windows 8.1

  - S8022452: Hotspot needs to know about Windows 8.1 and
    Windows Server 2012 R2

  - S8023990: Regression: postscript size increase from 6u18

  - S8024283: 10 nashorn tests fail with similar stack trace
    InternalError with cause being NoClassDefFoundError

  - S8024616: JSR292: lazily initialize core NamedFunctions
    used for bootstrapping

  - S8024648: 7141246 & 8016131 break Zero port (AArch64
    only)

  - S8024830: SEGV in
    org.apache.lucene.codecs.compressing.CompressingTermVect
    orsReader.get

  - S8025588: [macosx] Frozen AppKit thread in 7u40

  - S8026404: Logging in Applet can trigger ACE: access
    denied ('java.lang.RuntimePermission'
    'modifyThreadGroup')

  - S8026705: [TEST_BUG]
    java/beans/Introspector/TestTypeResolver.java failed

  - S8027196: Increment minor version of HSx for 7u55 and
    initialize the build number

  - S8027212:
    java/nio/channels/Selector/SelectAfterRead.java fails
    intermittently

  - S8028285: RMI Thread can no longer call out to AWT

  - S8029177: [Parfait] warnings from b117 for
    jdk.src.share.native.com.sun.java.util.jar: JNI
    exception pending

  - S8030655: Regression: 14_01 Security fix 8024306 causes
    test failures

  - S8030813: Signed applet fails to load when CRLs are
    stored in an LDAP directory

  - S8030822: (tz) Support tzdata2013i

  - S8031050: (thread) Change Thread initialization so that
    thread name is set before invoking SecurityManager

  - S8031075: [Regression] focus disappears with shift+tab
    on dialog having one focus component

  - S8031462: Fonts with morx tables are broken with latest
    ICU fixes

  - S8032585: JSR292: IllegalAccessError when attempting to
    invoke protected method from different package

  - S8032740: Need to create SE Embedded Source Bundles in 7
    Release

  - S8033278: Missed access checks for Lookup.unreflect*
    after 8032585

  - S8034772: JDK-8028795 brought a specification change to
    7u55 release and caused JCK7 signature test failure

  - S8035283: Second phase of branch shortening doesn't
    account for loop alignment

  - S8035613: With active Securitymanager
    JAXBContext.newInstance fails

  - S8035618: Four api/org_omg/CORBA TCK tests fail under
    plugin only

  - S8036147: Increment hsx 24.55 build to b02 for 7u55-b11

  - S8036786: Update jdk7 testlibrary to match jdk8

  - S8036837: Increment hsx 24.55 build to b03 for 7u55-b12

  - S8037012: (tz) Support tzdata2014a

  - S8038306: (tz) Support tzdata2014b

  - S8038392: Generating prelink cache breaks JAVA 'jinfo'
    utility normal behavior

  - S8042264: 7u65 l10n resource file translation update 1

  - S8042582: Test
    java/awt/KeyboardFocusmanager/ChangeKFMTest/ChangeKFMTes
    t.html fails on Windows x64

  - S8042590: Running form URL throws NPE

  - S8042789: org.omg.CORBA.ORBSingletonClass loading no
    longer uses context class loader

  - S8043012: (tz) Support tzdata2014c

  - S8004145: New improved hgforest.sh, ctrl-c now properly
    terminates mercurial processes.

  - S8007625: race with nested repos in
    /common/bin/hgforest.sh

  - S8011178: improve common/bin/hgforest.sh python
    detection (MacOS)

  - S8011342: hgforest.sh : 'python --version' not supported
    on older python

  - S8011350: hgforest.sh uses non-POSIX sh features that
    may fail with some shells

  - S8024200: handle hg wrapper with space after #!

  - S8025796: hgforest.sh could trigger unbuffered output
    from hg without complicated machinations

  - S8028388: 9 jaxws tests failed in nightly build with
    java.lang.ClassCastException

  - S8031477: [macosx] Loading AWT native library fails

  - S8032370: No 'Truncated file' warning from
    IIOReadWarningListener on JPEGImageReader

  - S8035834: InetAddress.getLocalHost() can hang after
    JDK-8030731 was fixed

  - S8009062: poor performance of JNI AttachCurrentThread
    after fix for 7017193

  - S8035893: JVM_GetVersionInfo fails to zero structure

  - Re-enable the 'gamma' test at the end of the HotSpot
    build, but only for HotSpot based bootstrap JDKs.

  - S8015976: OpenJDK part of bug JDK-8015812 [TEST_BUG]
    Tests have conflicting test descriptions

  - S8022698: javax/script/GetInterfaceTest.java fails since
    7u45 b04 with -agentvm option

  - S8022868: missing codepage Cp290 at java runtime

  - S8023310: Thread contention in the method
    Beans.IsDesignTime()

  - S8024461: [macosx] Java crashed on mac10.9 for swing and
    2d function manual test

  - S8025679: Increment minor version of HSx for 7u51 and
    initialize the build number

  - S8026037: [TESTBUG]
    sun/security/tools/jarsigner/warnings.sh test fails on
    Solaris

  - S8026304: jarsigner output bad grammar

  - S8026772:
    test/sun/util/resources/TimeZone/Bug6317929.java failing

  - S8026887: Make issues due to failed large pages
    allocations easier to debug

  - S8027204: Revise the update of 8026204 and 8025758

  - S8027224: test regression - ClassNotFoundException

  - S8027370: Support tzdata2013h

  - S8027378: Two closed/javax/xml/8005432 fails with
    jdk7u51b04

  - S8027787: 7u51 l10n resource file translation update 1

  - S8027837: JDK-8021257 causes CORBA build failure on
    emdedded platforms

  - S8027943: serial version of
    com.sun.corba.se.spi.orbutil.proxy.CompositeInvocationHa
    ndlerImpl changed in 7u45

  - S8027944: Increment hsx 24.51 build to b02 for 7u51-b07

  - S8028057: Modify jarsigner man page documentation to
    document CCC 8024302: Clarify jar verifications

  - S8028090: reverting change - changeset pushed with
    incorrect commit message, linked to wrong issue

  - S8028111: XML readers share the same entity expansion
    counter

  - S8028215: ORB.init fails with SecurityException if
    properties select the JDK default ORB

  - S8028293: Check local configuration for actual ephemeral
    port range

  - S8028382: Two javax/xml/8005433 tests still fail after
    the fix JDK-8028147

  - S8028453: AsynchronousSocketChannel.connect() requires
    SocketPermission due to bind to local address (win)

  - S8028823: java/net/Makefile tabs converted to spaces

  - S8029038: Revise fix for XML readers share the same
    entity expansion counter

  - S8029842: Increment hsx 24.51 build to b03 for 7u51-b11

  - Bug fixes

  - Fix accidental reversion of PR1188 for armel

  - PR1781: NSS PKCS11 provider fails to handle multipart
    AES encryption

  - PR1830: Drop version requirement for LCMS 2

  - PR1833, RH1022017: Report elliptic curves supported by
    NSS, not the SunEC library

  - RH905128: [CRASH] OpenJDK-1.7.0 while using NSS security
    provider and kerberos

  - PR1393: JPEG support in build is broken on
    non-system-libjpeg builds

  - PR1726: configure fails looking for ecj.jar before even
    trying to find javac

  - Red Hat local: Fix for repo with path statting with / .

  - Remove unused hgforest script

  - PR1101: Undefined symbols on GNU/Linux SPARC

  - PR1659: OpenJDK 7 returns incorrect TrueType font
    metrics when bold style is set

  - PR1677, G498288: Update PaX support to detect running
    PaX kernel and use newer tools

  - PR1679: Allow OpenJDK to build on PaX-enabled kernels

  - PR1684: Build fails with empty PAX_COMMAND

  - RH1015432: java-1.7.0-openjdk: Fails on PPC with
    StackOverflowError (revised fix)

  - Link against $(LIBDL) if SYSTEM_CUPS is not true

  - Perform configure checks using ecj.jar when --with-gcj
    (native ecj build) is enabled.

  - Fix broken bootstrap build by updating
    ecj-multicatch.patch

  - PR1653: Support ppc64le via Zero

  - PR1654: ppc32 needs a larger ThreadStackSize to build

  - RH1015432: java-1.7.0-openjdk: Fails on PPC with
    StackOverflowError

  - RH910107: fail to load PC/SC library

  - ARM32 port

  - Add arm_port from IcedTea 6

  - Add patches/arm.patch from IcedTea 6

  - Add patches/arm-debug.patch from IcedTea 6

  - Add patches/arm-hsdis.patch from IcedTea 6

  - added jvmti event generation for dynamic_generate and
    compiled_method_load events to ARM JIT compiler

  - Adjust saved SP when safepointing.

  - First cut of invokedynamic

  - Fix trashed thread ptr after recursive re-entry from asm
    JIT.

  - JIT-compilation of ldc methodHandle

  - Rename a bunch of misleadingly-named functions

  - Changes for HSX22

  - Rename a bunch of misleadingly-named functions

  - Patched method handle adapter code to deal with failures
    in TCK

  - Phase 1

  - Phase 2

  - RTC Thumb2 JIT enhancements.

  - Zero fails to build in hsx22+, fix for hsx22 after runs
    gamma OK, hsx23 still nogo.

  - Use ldrexd for atomic reads on ARMv7.

  - Use unified syntax for thumb code.

  - Corrected call from fast_method_handle_entry to
    CppInterpreter::method_handle_entry so that thread is
    loaded into r2

  - Don't save locals at a return.

  - Fix call to handle_special_method(). Fix
    compareAndSwapLong.

  - Fix JIT bug that miscompiles
    org.eclipse.ui.internal.contexts.ContextAuthority.source
    Changed

  - invokedynamic and aldc for JIT

  - Modified safepoint check to rely on memory protect
    signal instead of polling

  - Minor review cleanups.

  - PR1188: ASM Interpreter and Thumb2 JIT javac miscompile
    modulo reminder on armel

  - PR1363: Fedora 19 / rawhide FTBFS SIGILL

  - Changes for HSX23

  - Remove fragment from method that has been removed

  - Remove C++ flags from CC_COMPILE and fix usage in
    zeroshark.make.

  - Use $(CC) to compile mkbc instead of $(CC_COMPILE) to
    avoid C++-only flags

  - Add note about use of $(CFLAGS)/$(CXXFLAGS)/$(CPPFLAGS)
    at present.

  - Override automatic detection of source language for
    bytecodes_arm.def

  - Include $(CFLAGS) in assembler stage

  - PR1626: ARM32 assembler update for hsx24. Use ARM32JIT
    to turn it on/off.

  - Replace literal offsets for METHOD_SIZEOFPARAMETERS and
    ISTATE_NEXT_FRAME with correct symbolic names.

  - Turn ARM32 JIT on by default

  - AArch64 port

  - AArch64 C2 instruct for smull

  - Add a constructor as a conversion from Register -
    RegSet. Use it.

  - Add RegSet::operator+=.

  - Add support for a few simple intrinsics

  - Add support for builtin crc32 instructions

  - Add support for CRC32 intrinsic

  - Add support for Neon implementation of CRC32

  - All address constants are 48 bits in size.

  - C1: Fix offset overflow when profiling.

  - Common frame handling for C1/C2 which correctly handle
    all frame sizes

  - Correct costs for operations with shifts.

  - Correct OptoAssembly for prologs and epilogs.

  - Delete useless instruction.

  - Don't use any form of _call_VM_leaf when we're calling a
    stub.

  - Fast string comparison

  - Fast String.equals()

  - Fix a tonne of bogus comments.

  - Fix biased locking and enable as default

  - Fix instruction size from 8 to 4

  - Fix opto assembly for shifts.

  - Fix register misuse in verify_method_data_pointer

  - Fix register usage in generate_verify_oop().

  - Implement various locked memory operations.

  - Improve C1 performance improvements in ic_cache checks

  - Improve code generation for pop(), as suggested by
    Edward Nevill.

  - Improvements to safepoint polling

  - Make code entry alignment 64 for C2

  - Minor optimisation for divide by 2

  - New cost model for instruction selection.

  - Offsets in lookupswitch instructions should be signed.

  - Optimise addressing of card table byte map base

  - Optimise C2 entry point verification

  - Optimise long divide by 2

  - Performance improvement and ease of use changes pulled
    from upstream

  - Preserve callee save FP registers around call to java
    code

  - Remove obsolete C1 patching code.

  - Remove special-case handling of division arguments.
    AArch64 doesn't need it.

  - Remove unnecessary memory barriers around CAS operations

  - Restore sp from sender sp, r13 in crc32 code

  - Restrict default ReservedCodeCacheSize to 128M

  - Rewrite CAS operations to be more conservative

  - Save intermediate state before removing C1 patching
    code.

  - Tidy up register usage in push/pop instructions.

  - Tidy up stack frame handling.

  - Use 2- and 3-instruction immediate form of movoop and
    mov_metadata in C2-generated code.

  - Use an explicit set of registers rather than a bitmap
    for psh and pop operations.

  - Use explicit barrier instructions in C1.

  - Use gcc __clear_cache instead of doing it ourselves

  - PR1713: Support AArch64 Port

  - Shark

  - Add Shark definitions from 8003868

  - Drop compile_method argument removed in 7083786 from
    sharkCompiler.cpp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00056.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=887530"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_7_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-1.7.0.55-24.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-accessibility-1.7.0.55-24.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.55-24.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-debugsource-1.7.0.55-24.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-demo-1.7.0.55-24.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.55-24.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-devel-1.7.0.55-24.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.55-24.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-headless-1.7.0.55-24.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-headless-debuginfo-1.7.0.55-24.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-javadoc-1.7.0.55-24.17.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"java-1_7_0-openjdk-src-1.7.0.55-24.17.1") ) flag++;

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
