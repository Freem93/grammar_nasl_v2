#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-368.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74670);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/08/06 14:06:07 $");

  script_cve_id("CVE-2012-1711", "CVE-2012-1713", "CVE-2012-1716", "CVE-2012-1717", "CVE-2012-1718", "CVE-2012-1719", "CVE-2012-1723", "CVE-2012-1724", "CVE-2012-1725");
  script_osvdb_id(82874, 82877, 82878, 82879, 82880, 82882, 82883, 82884, 82886);

  script_name(english:"openSUSE Security Update : java-1_6_0-openjdk (openSUSE-SU-2012:0828-1)");
  script_summary(english:"Check for the openSUSE-2012-368 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This version upgrade of java-1_6_0-openjdk fixes multiple security
flaws :

  - S7079902, CVE-2012-1711: Refine CORBA data models

  - S7143606, CVE-2012-1717: File.createTempFile should be
    improved for temporary files created by the platform.

  - S7143614, CVE-2012-1716: SynthLookAndFeel stability
    improvement

  - S7143617, CVE-2012-1713: Improve fontmanager layout
    lookup operations

  - S7143851, CVE-2012-1719: Improve IIOP stub and tie
    generation in RMIC

  - S7143872, CVE-2012-1718: Improve certificate extension
    processing

  - S7152811, CVE-2012-1723: Issues in client compiler

  - S7157609, CVE-2012-1724: Issues with loop

  - S7160757, CVE-2012-1725: Problem with hotspot
    runtime_classfile"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-07/msg00008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=766802"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_6_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Field Bytecode Verifier Cache Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/26");
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
if (release !~ "^(SUSE11\.4|SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"java-1_6_0-openjdk-1.6.0.0_b24.1.11.3-0.11.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"java-1_6_0-openjdk-debuginfo-1.6.0.0_b24.1.11.3-0.11.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"java-1_6_0-openjdk-debugsource-1.6.0.0_b24.1.11.3-0.11.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"java-1_6_0-openjdk-demo-1.6.0.0_b24.1.11.3-0.11.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"java-1_6_0-openjdk-demo-debuginfo-1.6.0.0_b24.1.11.3-0.11.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"java-1_6_0-openjdk-devel-1.6.0.0_b24.1.11.3-0.11.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"java-1_6_0-openjdk-devel-debuginfo-1.6.0.0_b24.1.11.3-0.11.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"java-1_6_0-openjdk-javadoc-1.6.0.0_b24.1.11.3-0.11.2") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"java-1_6_0-openjdk-src-1.6.0.0_b24.1.11.3-0.11.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-1.6.0.0_b24.1.11.3-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-debuginfo-1.6.0.0_b24.1.11.3-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-debugsource-1.6.0.0_b24.1.11.3-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-demo-1.6.0.0_b24.1.11.3-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-demo-debuginfo-1.6.0.0_b24.1.11.3-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-devel-1.6.0.0_b24.1.11.3-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-devel-debuginfo-1.6.0.0_b24.1.11.3-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-javadoc-1.6.0.0_b24.1.11.3-6.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-src-1.6.0.0_b24.1.11.3-6.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_6_0-openjdk");
}
