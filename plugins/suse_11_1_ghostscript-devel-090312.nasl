#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update ghostscript-devel-592.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40219);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/21 20:09:51 $");

  script_cve_id("CVE-2009-0583", "CVE-2009-0584");

  script_name(english:"openSUSE Security Update : ghostscript-devel (ghostscript-devel-592)");
  script_summary(english:"Check for the ghostscript-devel-592 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Integer overflows and missing upper bounds checks in Ghostscript's ICC
library potentially allowed attackers to crash Ghostscript or even
cause execution of arbitrary code via specially crafted PS or PDF
files (CVE-2009-0583, CVE-2009-0584)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=483303"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ghostscript-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-fonts-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-fonts-rus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-fonts-std");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-ijs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-library");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-omni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ghostscript-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimpprint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgimpprint-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/12");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"ghostscript-devel-8.62-31.40.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ghostscript-fonts-other-8.62-31.40.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ghostscript-fonts-rus-8.62-31.40.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ghostscript-fonts-std-8.62-31.40.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ghostscript-ijs-devel-8.62-31.40.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ghostscript-library-8.62-31.40.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ghostscript-omni-8.62-31.40.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ghostscript-x11-8.62-31.40.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libgimpprint-4.2.7-31.40.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"libgimpprint-devel-4.2.7-31.40.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript-devel / ghostscript-fonts-other / ghostscript-fonts-rus / etc");
}
