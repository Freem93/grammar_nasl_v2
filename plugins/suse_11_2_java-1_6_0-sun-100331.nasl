#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update java-1_6_0-sun-2228.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(45465);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/06/13 20:00:36 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-0082", "CVE-2010-0084", "CVE-2010-0085", "CVE-2010-0087", "CVE-2010-0088", "CVE-2010-0089", "CVE-2010-0090", "CVE-2010-0091", "CVE-2010-0092", "CVE-2010-0093", "CVE-2010-0094", "CVE-2010-0095", "CVE-2010-0837", "CVE-2010-0838", "CVE-2010-0839", "CVE-2010-0840", "CVE-2010-0841", "CVE-2010-0842", "CVE-2010-0843", "CVE-2010-0844", "CVE-2010-0845", "CVE-2010-0846", "CVE-2010-0847", "CVE-2010-0848", "CVE-2010-0849", "CVE-2010-0850");

  script_name(english:"openSUSE Security Update : java-1_6_0-sun (java-1_6_0-sun-2228)");
  script_summary(english:"Check for the java-1_6_0-sun-2228 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Sun Java 6 was updated to Update 19, fixing a large number of security
issues.

CVE-2009-3555 CVE-2010-0082 CVE-2010-0084 CVE-2010-0085 CVE-2010-0087
CVE-2010-0088 CVE-2010-0089 CVE-2010-0090 CVE-2010-0091 CVE-2010-0092
CVE-2010-0093 CVE-2010-0094 CVE-2010-0095 CVE-2010-0837 CVE-2010-0838
CVE-2010-0839 CVE-2010-0840 CVE-2010-0841 CVE-2010-0842 CVE-2010-0843
CVE-2010-0844 CVE-2010-0845 CVE-2010-0846 CVE-2010-0847 CVE-2010-0848
CVE-2010-0849 CVE-2010-0850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=578877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=592589"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_6_0-sun packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java MixerSequencer Object GM_Song Structure Handling Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"java-1_6_0-sun-1.6.0.u19-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"java-1_6_0-sun-alsa-1.6.0.u19-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"java-1_6_0-sun-demo-1.6.0.u19-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"java-1_6_0-sun-devel-1.6.0.u19-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"java-1_6_0-sun-jdbc-1.6.0.u19-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"java-1_6_0-sun-plugin-1.6.0.u19-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"java-1_6_0-sun-src-1.6.0.u19-0.1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_6_0-sun");
}
