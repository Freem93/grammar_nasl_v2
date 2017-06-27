#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-622.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75101);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-1500", "CVE-2013-1571", "CVE-2013-2407", "CVE-2013-2412", "CVE-2013-2443", "CVE-2013-2444", "CVE-2013-2445", "CVE-2013-2446", "CVE-2013-2447", "CVE-2013-2448", "CVE-2013-2449", "CVE-2013-2450", "CVE-2013-2451", "CVE-2013-2452", "CVE-2013-2453", "CVE-2013-2454", "CVE-2013-2455", "CVE-2013-2456", "CVE-2013-2457", "CVE-2013-2458", "CVE-2013-2459", "CVE-2013-2460", "CVE-2013-2461", "CVE-2013-2463", "CVE-2013-2465", "CVE-2013-2469", "CVE-2013-2470", "CVE-2013-2471", "CVE-2013-2472", "CVE-2013-2473");

  script_name(english:"openSUSE Security Update : java-1_7_0-openjdk (openSUSE-SU-2013:1288-1)");
  script_summary(english:"Check for the openSUSE-2013-622 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"java-1_7_0-openjdk was updated to icedtea-2.4.1 (bnc#828665) 

  - Security fixes

  - S6741606, CVE-2013-2407: Integrate Apache Santuario

  - S7158805, CVE-2013-2445: Better rewriting of nested
    subroutine calls

  - S7170730, CVE-2013-2451: Improve Windows network stack
    support.

  - S8000638, CVE-2013-2450: Improve deserialization

  - S8000642, CVE-2013-2446: Better handling of objects for
    transportation

  - S8001032: Restrict object access

  - S8001033, CVE-2013-2452: Refactor network address
    handling in virtual machine identifiers

  - S8001034, CVE-2013-1500: Memory management improvements

  - S8001038, CVE-2013-2444: Resourcefully handle resources

  - S8001043: Clarify definition restrictions

  - S8001308: Update display of applet windows

  - S8001309: Better handling of annotation interfaces

  - S8001318, CVE-2013-2447: Socket.getLocalAddress not
    consistent with InetAddress.getLocalHost

  - S8001330, CVE-2013-2443: Improve on checking order
    (non-Zero builds only)

  - S8003703, CVE-2013-2412: Update RMI connection dialog
    box

  - S8004288, CVE-2013-2449: (fs) Files.probeContentType
    problems

  - S8004584: Augment applet contextualization

  - S8005007: Better glyph processing

  - S8006328, CVE-2013-2448: Improve robustness of sound
    classes

  - S8006611: Improve scripting

  - S8007467: Improve robustness of JMX internal APIs

  - S8007471: Improve MBean notifications

  - S8007812, CVE-2013-2455: (reflect)
    Class.getEnclosingMethod problematic for some classes

  - S8007925: Improve cmsStageAllocLabV2ToV4curves

  - S8007926: Improve cmsPipelineDup

  - S8007927: Improve cmsAllocProfileSequenceDescription

  - S8007929: Improve CurvesAlloc

  - S8008120, CVE-2013-2457: Improve JMX class checking

  - S8008124, CVE-2013-2453: Better compliance testing

  - S8008128: Better API coherence for JMX

  - S8008132, CVE-2013-2456: Better serialization support

  - S8008585: Better JMX data handling

  - S8008593: Better URLClassLoader resource management

  - S8008603: Improve provision of JMX providers

  - S8008607: Better input checking in JMX

  - S8008611: Better handling of annotations in JMX

  - S8008615: Improve robustness of JMX internal APIs

  - S8008623: Better handling of MBeanServers

  - S8008744, CVE-2013-2407: Rework part of fix for
    JDK-6741606

  - S8008982: Adjust JMX for underlying interface changes

  - S8009004: Better implementation of RMI connections

  - S8009008: Better manage management-api

  - S8009013: Better handling of T2K glyphs

  - S8009034: Improve resulting notifications in JMX

  - S8009038: Improve JMX notification support

  - S8009057, CVE-2013-2448: Improve MIDI event handling

  - S8009067: Improve storing keys in KeyStore

  - S8009071, CVE-2013-2459: Improve shape handling

  - S8009235: Improve handling of TSA data

  - S8009424, CVE-2013-2458: Adapt Nashorn to JSR-292
    implementation change

  - S8009554, CVE-2013-2454: Improve
    SerialJavaObject.getFields

  - S8009654: Improve stability of cmsnamed

  - S8010209, CVE-2013-2460: Better provision of factories

  - S8011243, CVE-2013-2470: Improve ImagingLib

  - S8011248, CVE-2013-2471: Better Component Rasters

  - S8011253, CVE-2013-2472: Better Short Component Rasters

  - S8011257, CVE-2013-2473: Better Byte Component Rasters

  - S8012375, CVE-2013-1571: Improve Javadoc framing

  - S8012421: Better positioning of PairPositioning

  - S8012438, CVE-2013-2463: Better image validation

  - S8012597, CVE-2013-2465: Better image channel
    verification

  - S8012601, CVE-2013-2469: Better validation of image
    layouts

  - S8014281, CVE-2013-2461: Better checking of XML
    signature

  - S8015997: Additional improvement in Javadoc framing

  - OpenJDK

  - list to long, please consult NEWS file

  - java-1.7.0-openjdk-zero-arch.patch: fix detection of
    zero arch

  - ignore rhino dependencies during a build to prevent a
    build cycle 

  - update to icedtea-2.4.0 (based on oracle jdk7u40)

  - OpenJDK (see NEWS for full listing)

  - PR1209, S7170638: Use DTRACE_PROBE[N] in JNI Set and
    SetStatic Field.

  - PR1206, S7201205: Add Makefile configuration option to
    build with unlimited crypto in OpenJDK

  - Backports

  - PR1197, S8003120, RH868136:
    ResourceManager.getApplicationResources() does not close
    InputStreams

  - S8014618, RH962568: Need to strip leading zeros in
    TlsPremasterSecret of DHKeyAgreement

  - Bug fixes

  - PR1212: IcedTea7 fails to build because
    Resources.getText() is no longer available for code to
    use

  - Add NSS (commented out) to other platforms.

  - Allow multiple PKCS11 library initialisation to be a
    non-critical error.

  - Complete switch from local zlib patch to upstream
    version.

  - Include defs.make in buildtree.make so ZERO_BUILD is
    recognised and JVM_VARIANT_ZERO set.

  - Provide support for using PKCS11 provider with NSS

  - Remove file apparently removed as part of upstreaming of
    Zero.

  - Revert 7060849

  - Set UNLIMITED_CRYPTO=true to ensure we use the unlimited
    policy.

  - PR473: Set handleStartupErrors to
    ignoreMultipleInitialisation in nss.cfg

  - PR716: IcedTea7 should bootstrap with IcedTea6

  - Expand java.security.cert.* imports to avoid conflict
    when building with OpenJDK 6.

  - Fix indentation on Makefile block not executed when
    STRIP_POLICY=no_strip is set

  - Fix invalid XSL stylesheets and DTD introduced as part
    of JEP 167.

  - Include defs.make in buildtree.make so ZERO_BUILD is
    recognised and JVM_VARIANT_ZERO set.

  - Make sure libffi cflags and libs are used.

  - PR1378: Add AArch64 support to Zero

  - PR1170: Ensure unlimited crypto policy is in place.

  - RH513605, PR1280: Updating/Installing OpenJDK should
    recreate the shared class-data archive

  - PR1358: Make XRender mandatory

  - PR1360: Check for /usr/lib64 JVMs and generic JPackage
    alternative

  - PR1435, D657854: OpenJDK 7 returns incorrect TrueType
    font metrics

  - PR728: GTKLookAndFeel does not honor
    gtk-alternative-button-order

  - JamVM

  - JSR 335: (lambda expressions) initial hack

  - JEP 171: Implement fence methods in sun.misc.Unsafe

  - Fix invokesuper check in invokespecial opcode

  - Fix non-direct interpreter invokespecial super-class
    check

  - When GC'ing a native method don't try to free code

  - Do not free unprepared Miranda method code data

  - Set anonymous class protection domain

  - JVM_IsVMGeneratedMethodIx stub

  - Dummy implementation of sun.misc.Perf natives

  - separate vm for zero is no longer needed

  - drop java-1.7.0-openjdk-aarch64.patch (upstream: PR1378)

  - fix bnc#781690c#11 - setup JAVA_HOME in posttrans, so
    certificates will be created by this JVM

  - fix the postrans conditions (add missing prefiX)

  - relax build requires, so every java-devel >= 1.7.0 can
    match"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-08/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=781690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828665"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_7_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java storeImageArray() Invalid Array Indexing Vulnerability');
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/24");
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

if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-1.7.0.6-3.41.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.6-3.41.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-debugsource-1.7.0.6-3.41.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-demo-1.7.0.6-3.41.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.6-3.41.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-devel-1.7.0.6-3.41.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.6-3.41.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-javadoc-1.7.0.6-3.41.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-src-1.7.0.6-3.41.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-1.7.0.6-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.6-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-debugsource-1.7.0.6-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-demo-1.7.0.6-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.6-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-devel-1.7.0.6-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.6-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-javadoc-1.7.0.6-8.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-src-1.7.0.6-8.18.1") ) flag++;

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
