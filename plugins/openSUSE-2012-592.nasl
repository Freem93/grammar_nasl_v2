#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-592.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74748);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/20 14:21:42 $");

  script_cve_id("CVE-2012-0547", "CVE-2012-1682", "CVE-2012-3136", "CVE-2012-4681");
  script_bugtraq_id(55213, 55336, 55337, 55339);

  script_name(english:"openSUSE Security Update : java-1_7_0-openjdk (openSUSE-SU-2012:1154-1)");
  script_summary(english:"Check for the openSUSE-2012-592 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Java-1_7_0-openjdk was updated to fix a remote exploit
(CVE-2012-4681).

Also bugfixes were done :

  - fix build on ARM and i586

  - remove files that are no longer used

  - zero build can be enabled using rpmbuild (osc build)
    --with zero

  - add hotspot 2.1 needed for zero

  - fix filelist on %{ix86}

  - Security fixes

  - S7162476, CVE-2012-1682: XMLDecoder security issue via
    ClassFinder

  - S7194567, CVE-2012-3136: Improve long term persistence
    of java.beans objects

  - S7163201, CVE-2012-0547: Simplify toolkit internals
    references

  - RH852051, CVE-2012-4681, S7162473: Reintroduce
    PackageAccessible checks removed in 6788531.

  - OpenJDK

  - Fix Zero FTBFS issues with 2.3

  - S7180036: Build failure in Mac platform caused by fix #
    7163201

  - S7182135: Impossible to use some editors directly

  - S7183701: [TEST]
    closed/java/beans/security/TestClassFinder.java &ndash;
    compilation failed

  - S7185678:
    java/awt/Menu/NullMenuLabelTest/NullMenuLabelTest.java
    failed with NPE

  - Bug fixes

  - PR1149: Zero-specific patch files not being packaged

  - use icedtea tarball for build again, this led into
    following dropped files because the are already in the
    tarball and simplified %prep and %build

  - drop class-rewriter.tar.gz

  - drop systemtap-tapset.tar.gz

  - drop desktop-files.tar.gz

  - drop nss.cfg

  - drop pulseaudio.tar.gz

  - drop remove-intree-libraries.sh

  - add archives from icedtea7-forest-2.3 for openjdk,
    corba, jaxp, jaxws, jdk, langtools and hotspot

  - drop rhino.patch, pulse-soundproperties and systemtap
    patch

  - move gnome bridge patches before make as it's irritating
    to have the patch fail after openjdk is built

  - use explicit file attributes in %files sections to
    prevent the file permissions problems in a future (like
    bnc#770040)

  - changed version scheme, so it now matches Oracle Java
    1.7.0.6 == Java7 u 6

  - update to icedtea-2.3.1 / OpenJDK7 u6 (bnc#777499)

  - Security fixes

  - RH852051, CVE-2012-4681: Reintroduce PackageAccessible
    checks removed in 6788531.

  - Bug fixes

  - PR902: PulseAudioClip getMicrosecondsLength() returns
    length in milliseconds, not microseconds

  - PR986: IcedTea7 fails to build with IcedTea6 CACAO due
    to low max heapsize

  - PR1050: Stream objects not garbage collected

  - PR1119: Only add classes to rt-source-files.txt if the
    class (or one or more of its methods/fields) are
    actually missing from the boot JDK

  - PR1137: Allow JARs to be optionally compressed by
    setting COMPRESS_JARS

  - OpenJDK

  - Make dynamic support for GConf work again.

  - PR1095: Add configure option for -Werror

  - PR1101: Undefined symbols on GNU/Linux SPARC

  - PR1140: Unnecessary diz files should not be installed

  - S7192804, PR1138: Build should not install jvisualvm man
    page for OpenJDK

  - JamVM

  - ARMv6 armhf: Changes for Raspbian (Raspberry Pi)

  - PPC: Don't use lwsync if it isn't supported

  - X86: Generate machine-dependent stubs for i386

  - When suspending, ignore detached threads that have died,
    this prevents a user caused deadlock when an external
    thread has been attached to the VM via JNI and it has
    exited without detaching

  - Add missing REF_TO_OBJs for references passed from JNI,
    this enable JamVM to run Qt-Jambi

  - there are number of fixes in 2.3, see NEWS"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-09/msg00052.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=770040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777499"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_7_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java 7 Applet Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-1.7.0.6-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.6-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-debugsource-1.7.0.6-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-demo-1.7.0.6-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.6-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-devel-1.7.0.6-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.6-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-javadoc-1.7.0.6-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-src-1.7.0.6-3.12.1") ) flag++;

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
