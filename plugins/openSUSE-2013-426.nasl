#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-426.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74999);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:13 $");

  script_cve_id("CVE-2013-0401", "CVE-2013-1488", "CVE-2013-1518", "CVE-2013-1537", "CVE-2013-1557", "CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2415", "CVE-2013-2417", "CVE-2013-2419", "CVE-2013-2420", "CVE-2013-2421", "CVE-2013-2422", "CVE-2013-2423", "CVE-2013-2424", "CVE-2013-2426", "CVE-2013-2429", "CVE-2013-2430", "CVE-2013-2431", "CVE-2013-2436");

  script_name(english:"openSUSE Security Update : java-1_7_0-openjdk (openSUSE-SU-2013:0964-1)");
  script_summary(english:"Check for the openSUSE-2013-426 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - update to icedtea-2.3.9 (bnc#816720) 

  - Security fixes

  - S6657673, CVE-2013-1518: Issues with JAXP

  - S7200507: Refactor Introspector internals

  - S8000724, CVE-2013-2417: Improve networking
    serialization

  - S8001031, CVE-2013-2419: Better font processing

  - S8001040, CVE-2013-1537: Rework RMI model

  - S8001322: Refactor deserialization

  - S8001329, CVE-2013-1557: Augment RMI logging

  - S8003335: Better handling of Finalizer thread

  - S8003445: Adjust JAX-WS to focus on API

  - S8003543, CVE-2013-2415: Improve processing of MTOM
    attachments

  - S8004261: Improve input validation

  - S8004336, CVE-2013-2431: Better handling of method
    handle intrinsic frames

  - S8004986, CVE-2013-2383: Better handling of glyph table

  - S8004987, CVE-2013-2384: Improve font layout

  - S8004994, CVE-2013-1569: Improve checking of glyph table

  - S8005432: Update access to JAX-WS

  - S8005943: (process) Improved Runtime.exec

  - S8006309: More reliable control panel operation

  - S8006435, CVE-2013-2424: Improvements in JMX

  - S8006790: Improve checking for windows

  - S8006795: Improve font warning messages

  - S8007406: Improve accessibility of AccessBridge

  - S8007617, CVE-2013-2420: Better validation of images

  - S8007667, CVE-2013-2430: Better image reading

  - S8007918, CVE-2013-2429: Better image writing

  - S8008140: Better method handle resolution

  - S8009049, CVE-2013-2436: Better method handle binding

  - S8009063, CVE-2013-2426: Improve reliability of
    ConcurrentHashMap

  - S8009305, CVE-2013-0401: Improve AWT data transfer

  - S8009677, CVE-2013-2423: Better setting of setters

  - S8009699, CVE-2013-2421: Methodhandle lookup

  - S8009814, CVE-2013-1488: Better driver management

  - S8009857, CVE-2013-2422: Problem with plugin

  - Backports

  - S7130662, RH928500: GTK file dialog crashes with a NPE

  - Bug fixes

  - PR1363: Fedora 19 / rawhide FTBFS SIGILL

  - PR1401: Fix Zero build on 2.3.8

  - Fix offset problem in ICU LETableReference.

  - Change -Werror fix to preserve OpenJDK default.

  - PR1303: Correct #ifdef to #if

  - PR1404: Failure to bootstrap with ecj 4.2

  - Added url as source. Please see
    http://en.opensuse.org/SourceUrls

  - icedtea-2.3.8-zero-patches.patch: remove patch not
    applicable to zero compatible hotspot

  - java-1.7.0-openjdk-fork.patch: Add support for
    architectures without fork syscall

  - java-1.7.0-openjdk-aarch64.patch: Add support for
    aarch64"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://en.opensuse.org/SourceUrls"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00099.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816720"
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
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Reflection Type Confusion Remote Code Execution');
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/04");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-1.7.0.6-8.14.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.6-8.14.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-debugsource-1.7.0.6-8.14.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-demo-1.7.0.6-8.14.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.6-8.14.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-devel-1.7.0.6-8.14.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.6-8.14.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-javadoc-1.7.0.6-8.14.5") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-src-1.7.0.6-8.14.5") ) flag++;

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
