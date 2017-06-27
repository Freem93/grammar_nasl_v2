#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update java-1_5_0-sun-1529.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(42460);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/21 20:09:51 $");

  script_cve_id("CVE-2009-3864", "CVE-2009-3867", "CVE-2009-3868", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3872", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875", "CVE-2009-3876", "CVE-2009-3877");

  script_name(english:"openSUSE Security Update : java-1_5_0-sun (java-1_5_0-sun-1529)");
  script_summary(english:"Check for the java-1_5_0-sun-1529 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"java-1_5_0-sun u22 update fixes the following security bugs :

  - CVE-2009-3864: CVSS v2 Base Score: 7.5

  - CVE-2009-3867: CVSS v2 Base Score: 9.3

  - CVE-2009-3868: CVSS v2 Base Score: 9.3

  - CVE-2009-3869: CVSS v2 Base Score: 9.3

  - CVE-2009-3871: CVSS v2 Base Score: 9.3

  - CVE-2009-3872: CVSS v2 Base Score: 10.0

  - CVE-2009-3873: CVSS v2 Base Score: n/a

  - CVE-2009-3874: CVSS v2 Base Score: 9.3

  - CVE-2009-3875: CVSS v2 Base Score: 5.0

  - CVE-2009-3876: CVSS v2 Base Score: 5.0

  - CVE-2009-3877: CVSS v2 Base Score: 5.0 For bug details
    use the CVE-ID to query the Mitre database at
    http://cve.mitre.org/cve please."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cve.mitre.org/cve"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=552581"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_5_0-sun packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119, 189, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_5_0-sun-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"java-1_5_0-sun-1.5.0_update22-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_5_0-sun-alsa-1.5.0_update22-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_5_0-sun-devel-1.5.0_update22-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_5_0-sun-jdbc-1.5.0_update22-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_5_0-sun-plugin-1.5.0_update22-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"java-1_5_0-sun-src-1.5.0_update22-0.1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_5_0-sun");
}
