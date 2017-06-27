#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-954.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87628);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2015-8327", "CVE-2015-8560");

  script_name(english:"openSUSE Security Update : cups-filters (openSUSE-2015-954)");
  script_summary(english:"Check for the openSUSE-2015-954 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for cups-filters fixes the following issues :

  - cups-filters-1.0.58-CVE-2015-8327-et_alii.patch adds
    back tick and semicolon to the list of illegal shell
    escape characters to fix CVE-2015-8327 and CVE-2015-8560
    (boo#957531)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957531"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cups-filters packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-filters-cups-browsed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-filters-cups-browsed-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-filters-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-filters-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-filters-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-filters-foomatic-rip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-filters-foomatic-rip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-filters-ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-filters-ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"cups-filters-1.0.58-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cups-filters-cups-browsed-1.0.58-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cups-filters-cups-browsed-debuginfo-1.0.58-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cups-filters-debuginfo-1.0.58-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cups-filters-debugsource-1.0.58-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cups-filters-devel-1.0.58-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cups-filters-foomatic-rip-1.0.58-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cups-filters-foomatic-rip-debuginfo-1.0.58-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cups-filters-ghostscript-1.0.58-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cups-filters-ghostscript-debuginfo-1.0.58-2.11.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups-filters / cups-filters-cups-browsed / etc");
}
