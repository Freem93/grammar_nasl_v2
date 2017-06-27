#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libpoppler-devel-3336.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(53755);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/06/13 20:00:36 $");

  script_cve_id("CVE-2010-3702", "CVE-2010-3703", "CVE-2010-3704");

  script_name(english:"openSUSE Security Update : libpoppler-devel (openSUSE-SU-2010:0976-1)");
  script_summary(english:"Check for the libpoppler-devel-3336 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Specially crafted PDF files could crash poppler or potentially even
cause execution of arbitrary code (CVE-2010-3702, CVE-2010-3704)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2010-11/msg00036.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=642785"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpoppler-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-glib4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-qt2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-qt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-qt4-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler-qt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpoppler5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE11.2", reference:"libpoppler-devel-0.12.3-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpoppler-glib-devel-0.12.3-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpoppler-glib4-0.12.3-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpoppler-qt2-0.12.3-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpoppler-qt3-devel-0.12.3-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpoppler-qt4-3-0.12.3-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpoppler-qt4-devel-0.12.3-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libpoppler5-0.12.3-1.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"poppler-tools-0.12.3-1.2.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "poppler");
}
