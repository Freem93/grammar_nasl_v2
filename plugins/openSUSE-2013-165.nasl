#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-165.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74907);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/08/06 14:06:07 $");

  script_cve_id("CVE-2013-0424", "CVE-2013-0425", "CVE-2013-0426", "CVE-2013-0427", "CVE-2013-0428", "CVE-2013-0429", "CVE-2013-0431", "CVE-2013-0432", "CVE-2013-0433", "CVE-2013-0434", "CVE-2013-0435", "CVE-2013-0440", "CVE-2013-0441", "CVE-2013-0442", "CVE-2013-0443", "CVE-2013-0444", "CVE-2013-0450", "CVE-2013-1475", "CVE-2013-1476", "CVE-2013-1478", "CVE-2013-1480");
  script_osvdb_id(89613, 89758, 89760, 89761, 89762, 89763, 89767, 89769, 89771, 89772, 89785, 89786, 89792, 89795, 89796, 89798, 89800, 89801, 89802, 89804, 89806);

  script_name(english:"openSUSE Security Update : java-1_7_0-openjdk (openSUSE-SU-2013:0377-1)");
  script_summary(english:"Check for the openSUSE-2013-165 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"java-1_7_0-openjdk was updated to icedtea-2.3.6 (bnc#803379)
containing various security and bugfixes :

  - Security fixes

  - S6563318, CVE-2013-0424: RMI data sanitization

  - S6664509, CVE-2013-0425: Add logging context

  - S6664528, CVE-2013-0426: Find log level matching its
    name or value given at construction time

  - S6776941: CVE-2013-0427: Improve thread pool shutdown

  - S7141694, CVE-2013-0429: Improving CORBA internals

  - S7173145: Improve in-memory representation of
    splashscreens

  - S7186945: Unpack200 improvement

  - S7186946: Refine unpacker resource usage

  - S7186948: Improve Swing data validation

  - S7186952, CVE-2013-0432: Improve clipboard access

  - S7186954: Improve connection performance

  - S7186957: Improve Pack200 data validation

  - S7192392, CVE-2013-0443: Better validation of client
    keys

  - S7192393, CVE-2013-0440: Better Checking of order of TLS
    Messages

  - S7192977, CVE-2013-0442: Issue in toolkit thread

  - S7197546, CVE-2013-0428: (proxy) Reflect about creating
    reflective proxies

  - S7200491: Tighten up JTable layout code

  - S7200493, CVE-2013-0444: Improve cache handling

  - S7200499: Better data validation for options

  - S7200500: Launcher better input validation

  - S7201064: Better dialogue checking

  - S7201066, CVE-2013-0441: Change modifiers on unused
    fields

  - S7201068, CVE-2013-0435: Better handling of UI elements

  - S7201070: Serialization to conform to protocol

  - S7201071, CVE-2013-0433: InetSocketAddress serialization
    issue

  - S8000210: Improve JarFile code quality

  - S8000537, CVE-2013-0450: Contextualize
    RequiredModelMBean class

  - S8000539, CVE-2013-0431: Introspect JMX data handling

  - S8000540, CVE-2013-1475: Improve IIOP type reuse
    management

  - S8000631, CVE-2013-1476: Restrict access to class
    constructor

  - S8001235, CVE-2013-0434: Improve JAXP HTTP handling

  - S8001242: Improve RMI HTTP conformance

  - S8001307: Modify ACC_SUPER behavior

  - S8001972, CVE-2013-1478: Improve image processing

  - S8002325, CVE-2013-1480: Improve management of images

  - Backports

  - S7057320:
    test/java/util/concurrent/Executors/AutoShutdown.java
    failing intermittently

  - S7083664: TEST_BUG: test hard code of using c:/temp but
    this dir might not exist

  - S7107613: scalability blocker in
    javax.crypto.CryptoPermissions

  - S7107616: scalability blocker in
    javax.crypto.JceSecurityManager

  - S7146424: Wildcard expansion for single entry classpath

  - S7160609: [macosx] JDK crash in libjvm.dylib ( C
    [GeForceGLDriver+0x675a] gldAttachDrawable+0x941)

  - S7160951: [macosx] ActionListener called twice for
    JMenuItem using ScreenMenuBar

  - S7162488: VM not printing unknown -XX options

  - S7169395: Exception throws due to the changes in JDK 7
    object tranversal and break backward compatibility

  - S7175616: Port fix for TimeZone from JDK 8 to JDK 7

  - S7176485: (bf) Allow temporary buffer cache to grow to
    IOV_MAX

  - S7179908: Fork hs23.3 hsx from hs22.2 for jdk7u7 and
    reinitialize build number

  - S7184326: TEST_BUG:
    java/awt/Frame/7024749/bug7024749.java has a typo

  - S7185245: Licensee source bundle tries to compile JFR

  - S7185471: Avoid key expansion when AES cipher is re-init
    w/ the same key

  - S7186371: [macosx] Main menu shortcuts not displayed
    (7u6 regression)

  - S7187834: [macosx] Usage of private API in macosx 2d
    implementation causes Apple Store rejection

  - S7188114: (launcher) need an alternate command line
    parser for Windows

  - S7189136: Fork hs23.5 hsx from hs23.4 for jdk7u9 and
    reinitialize build number

  - S7189350: Fix failed for CR 7162144

  - S7190550: REGRESSION: Some closed/com/oracle/jfr/api
    tests fail to compile because of fix 7185245

  - S7193219: JComboBox serialization fails in JDK 1.7

  - S7193977: REGRESSION:Java 7's JavaBeans persistence
    ignoring the 'transient' flag on properties

  - S7195106: REGRESSION : There is no way to get Icon inf,
    once Softreference is released

  - S7195301: XML Signature DOM implementation should not
    use instanceof to determine type of Node

  - S7195931: UnsatisfiedLinkError on
    PKCS11.C_GetOperationState while using NSS from jre7u6+

  - S7197071: Makefiles for various security providers
    aren't including the default manifest.

  - S7197652: Impossible to run any signed JNLP applications
    or applets, OCSP off by default

  - S7198146: Another new regression test does not compile
    on windows-amd64

  - S7198570: (tz) Support tzdata2012f

  - S7198640: new hotspot build - hs23.6-b04

  - S7199488: [TEST] runtime/7158800/InternTest.java failed
    due to false-positive on PID match.

  - S7199645: Increment build # of hs23.5 to b02

  - S7199669: Update tags in .hgtags file for CPU release
    rename

  - S7200720: crash in net.dll during NTLM authentication

  - S7200742: (se) Selector.select does not block when
    starting Coherence (sol11u1)

  - S7200762: [macosx] Stuck in
    sun.java2d.opengl.CGLGraphicsConfig.getMaxTextureSize(Na
    tive Method)

  - S8000285: Deadlock between PostEventQueue.noEvents,
    EventQueue.isDispatchThread and
    SwingUtilities.invokeLater

  - S8000286: [macosx] Views keep scrolling back to the drag
    position after DnD

  - S8000297: REGRESSION:
    closed/java/awt/EventQueue/PostEventOrderingTest.java
    fails

  - S8000307: Jre7cert: focusgained does not get called for
    all focus req when do alt + tab

  - S8000822: Fork hs23.7 hsx from hs23.6 for jdk7u11 and
    reinitialize build number

  - S8001124: jdk7u ProblemList.txt updates (10/2012)

  - S8001242: Improve RMI HTTP conformance

  - S8001808: Create a test for 8000327

  - S8001876: Create regtest for 8000283

  - S8002068: Build broken: corba code changes unable to use
    new JDK 7 classes

  - S8002091: tools/launcher/ToolsOpts.java test started to
    fail since 7u11 b01 on Windows

  - S8002114: fix failed for JDK-7160951: [macosx]
    ActionListener called twice for JMenuItem using
    ScreenMenuBar

  - S8002225: (tz) Support tzdata2012i

  - S8003402: (dc)
    test/java/nio/channels/DatagramChannel/SendToUnresovled.
    java failing after 7u11 cleanup issues

  - S8003403: Test ShortRSAKeyWithinTLS and
    ClientJSSEServerJSSE failing after 7u11 cleanup

  - S8003948: NTLM/Negotiate authentication problem

  - S8004175: Restricted packages added in java.security are
    missing in java.security-{macosx, solaris, windows}

  - S8004302: javax/xml/soap/Test7013971.java fails since
    jdk6u39b01

  - S8004341: Two JCK tests fails with 7u11 b06

  - S8005615: Java Logger fails to load tomcat logger
    implementation (JULI)

  - Bug fixes

  - Fix build using Zero's HotSpot so all patches apply
    again.

  - PR1295: jamvm parallel unpack failure

  - removed icedtea-2.3.2-fix-extract-jamvm-dependency.patch

  - removed
    icedtea-2.3.3-refresh-6924259-string_offset.patch

  - few missing /openjdk/%{origin}/ changes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-03/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=803379"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_7_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet JMX Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-1.7.0.6-3.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.6-3.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-debugsource-1.7.0.6-3.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-demo-1.7.0.6-3.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.6-3.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-devel-1.7.0.6-3.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.6-3.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-javadoc-1.7.0.6-3.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-src-1.7.0.6-3.26.1") ) flag++;

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
