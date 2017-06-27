#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update OpenOffice_org-4769.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(29240);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 20:31:04 $");

  script_cve_id("CVE-2007-4575");

  script_name(english:"openSUSE 10 Security Update : OpenOffice_org (OpenOffice_org-4769)");
  script_summary(english:"Check for the OpenOffice_org-4769 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of OpenOffice_org adds restrictions to SQL statements of
Java-based databases to avoid the execution of native Jave code by
creating procedures. (CVE-2007-4575)"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected OpenOffice_org packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-mailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-pyuno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-testtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-writer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.3", reference:"OpenOffice_org-2.3.0.1.2-10.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"OpenOffice_org-base-2.3.0.1.2-10.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"OpenOffice_org-calc-2.3.0.1.2-10.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"OpenOffice_org-devel-2.3.0.1.2-10.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"OpenOffice_org-draw-2.3.0.1.2-10.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"OpenOffice_org-filters-2.3.0.1.2-10.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"OpenOffice_org-gnome-2.3.0.1.2-10.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"OpenOffice_org-impress-2.3.0.1.2-10.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"OpenOffice_org-kde-2.3.0.1.2-10.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"OpenOffice_org-mailmerge-2.3.0.1.2-10.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"OpenOffice_org-math-2.3.0.1.2-10.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"OpenOffice_org-mono-2.3.0.1.2-10.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"OpenOffice_org-officebean-2.3.0.1.2-10.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"OpenOffice_org-pyuno-2.3.0.1.2-10.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"OpenOffice_org-sdk-2.3.0.1.2-10.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"OpenOffice_org-testtool-2.3.0.1.2-10.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"OpenOffice_org-writer-2.3.0.1.2-10.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenOffice_org");
}
