#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update ruby-123.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40121);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/21 20:09:50 $");

  script_cve_id("CVE-2008-1145", "CVE-2008-1891", "CVE-2008-2662", "CVE-2008-2663", "CVE-2008-2664", "CVE-2008-2725", "CVE-2008-2726");

  script_name(english:"openSUSE Security Update : ruby (ruby-123)");
  script_summary(english:"Check for the ruby-123 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of ruby fixes :

  - a possible information leakage (CVE-2008-1145) 

  - a directory traversal bug (CVE-2008-1891) in WEBrick 

  - various memory corruptions and integer overflows in
    array and string handling (CVE-2008-2662, CVE-2008-2663,
    CVE-2008-2664, CVE-2008-2725, CVE-2008-2726,
    CVE-2008-2727, CVE-2008-2728)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=368618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=383299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=397346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=405339"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(22, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-doc-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-test-suite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ruby-tk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"ruby-1.8.6.p114-6.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"ruby-devel-1.8.6.p114-6.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"ruby-doc-html-1.8.6.p114-6.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"ruby-doc-ri-1.8.6.p114-6.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"ruby-examples-1.8.6.p114-6.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"ruby-test-suite-1.8.6.p114-6.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"ruby-tk-1.8.6.p114-6.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby");
}
