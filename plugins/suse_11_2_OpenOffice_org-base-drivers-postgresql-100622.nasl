#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update OpenOffice_org-base-drivers-postgresql-2578.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(47757);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/06/13 20:00:37 $");

  script_cve_id("CVE-2010-0395");

  script_name(english:"openSUSE Security Update : OpenOffice_org-base-drivers-postgresql (openSUSE-SU-2010:0386-1)");
  script_summary(english:"Check for the OpenOffice_org-base-drivers-postgresql-2578 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of OpenOffice_org does not allow macros written in Python
to be executed without permission, CVE-2010-0395."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-07/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=607095"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected OpenOffice_org-base-drivers-postgresql packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-base-drivers-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-libs-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-libs-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-libs-core-l10n-prebuilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:OpenOffice_org-mailmerge");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/19");
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

if ( rpm_check(release:"SUSE11.2", reference:"OpenOffice_org-base-drivers-postgresql-3.1.1.4-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"OpenOffice_org-gnome-3.1.1.4-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"OpenOffice_org-kde-3.1.1.4-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"OpenOffice_org-kde4-3.1.1.4-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"OpenOffice_org-libs-core-3.1.1.4-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"OpenOffice_org-libs-core-devel-3.1.1.4-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"OpenOffice_org-libs-core-l10n-prebuilt-3.1.1.4-1.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"OpenOffice_org-mailmerge-3.1.1.4-1.3.1") ) flag++;

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
