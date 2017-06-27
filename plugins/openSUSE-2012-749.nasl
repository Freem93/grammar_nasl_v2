#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-749.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74793);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/06/17 14:46:28 $");

  script_cve_id("CVE-2012-3216", "CVE-2012-4416", "CVE-2012-5068", "CVE-2012-5069", "CVE-2012-5070", "CVE-2012-5071", "CVE-2012-5072", "CVE-2012-5073", "CVE-2012-5074", "CVE-2012-5075", "CVE-2012-5076", "CVE-2012-5077", "CVE-2012-5079", "CVE-2012-5081", "CVE-2012-5084", "CVE-2012-5085", "CVE-2012-5086", "CVE-2012-5087", "CVE-2012-5088", "CVE-2012-5089");
  script_osvdb_id(86344, 86345, 86346, 86347, 86348, 86349, 86350, 86351, 86352, 86353, 86354, 86355, 86356, 86357, 86358, 86359, 86360, 86361, 86362, 86363, 86364, 86365, 86366, 86367, 86368, 86369, 86370, 86371, 86372, 86374);

  script_name(english:"openSUSE Security Update : java-1_7_0-openjdk (openSUSE-SU-2012:1419-1)");
  script_summary(english:"Check for the openSUSE-2012-749 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"java-1_7_0-opendjk was updated to icedtea-2.3.3 (bnc#785814)

  - Security fixes

  - S6631398, CVE-2012-3216: FilePermission improved path
    checking

  - S7093490: adjust package access in rmiregistry

  - S7143535, CVE-2012-5068: ScriptEngine corrected
    permissions

  - S7158796, CVE-2012-5070: Tighten properties checking in
    EnvHelp

  - S7158807: Revise stack management with volatile call
    sites

  - S7163198, CVE-2012-5076: Tightened package accessibility

  - S7167656, CVE-2012-5077: Multiple Seeders are being
    created

  - S7169884, CVE-2012-5073: LogManager checks do not work
    correctly for sub-types

  - S7169887, CVE-2012-5074: Tightened package accessibility

  - S7169888, CVE-2012-5075: Narrowing resource definitions
    in JMX RMI connector

  - S7172522, CVE-2012-5072: Improve DomainCombiner checking

  - S7186286, CVE-2012-5081: TLS implementation to better
    adhere to RFC

  - S7189103, CVE-2012-5069: Executors needs to maintain
    state

  - S7189490: More improvements to DomainCombiner checking

  - S7189567, CVE-2012-5085: java net obselete protocol

  - S7192975, CVE-2012-5071: Issue with JMX reflection

  - S7195194, CVE-2012-5084: Better data validation for
    Swing

  - S7195549, CVE-2012-5087: Better bean object persistence

  - S7195917, CVE-2012-5086: XMLDecoder parsing at
    close-time should be improved

  - S7195919, CVE-2012-5079: (sl) ServiceLoader can throw
    CCE without needing to create instance

  - S7196190, CVE-2012-5088: Improve method of handling
    MethodHandles

  - S7198296, CVE-2012-5089: Refactor classloader usage

  - S7158800: Improve storage of symbol tables

  - S7158801: Improve VM CompileOnly option

  - S7158804: Improve config file parsing

  - S7198606, CVE-2012-4416: Improve VM optimization

  - Bug fixes

  - Remove merge artefact."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-10/msg00095.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=785814"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_7_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Method Handle Remote Code Execution');
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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/23");
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

if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-1.7.0.6-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.6-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-debugsource-1.7.0.6-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-demo-1.7.0.6-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.6-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-devel-1.7.0.6-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.6-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-javadoc-1.7.0.6-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-src-1.7.0.6-3.16.1") ) flag++;

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
