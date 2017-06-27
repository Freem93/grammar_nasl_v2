#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update OpenOffice_org-1187.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40881);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/21 20:09:50 $");

  script_cve_id("CVE-2009-0200", "CVE-2009-0201", "CVE-2009-2139", "CVE-2009-2140");

  script_name(english:"openSUSE Security Update : OpenOffice_org (OpenOffice_org-1187)");
  script_summary(english:"Check for the OpenOffice_org-1187 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of OpenOffice.org fixes potential buffer overflow in EMF
parser code (CVE-2009-2139, CVE-2009-2140) (Thanks to Petr Mladek).
Additionally Secunia reported an integer underflow (CVE-2009-0200) and
a buffer overflow (CVE-2009-0201) that could be triggered while
parsing Word documents."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=437666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=514085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=514089"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected OpenOffice_org packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-icon-themes-prebuilt");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/08");
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

if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-2.4.0.14-1.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-base-2.4.0.14-1.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-branding-upstream-2.4.0.14-1.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-calc-2.4.0.14-1.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-devel-2.4.0.14-1.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-draw-2.4.0.14-1.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-filters-2.4.0.14-1.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-gnome-2.4.0.14-1.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-icon-themes-prebuilt-2.4.0.14-1.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-impress-2.4.0.14-1.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-kde-2.4.0.14-1.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-mailmerge-2.4.0.14-1.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-math-2.4.0.14-1.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-mono-2.4.0.14-1.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-officebean-2.4.0.14-1.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-pyuno-2.4.0.14-1.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-sdk-2.4.0.14-1.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-testtool-2.4.0.14-1.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"OpenOffice_org-writer-2.4.0.14-1.4") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenOffice");
}
