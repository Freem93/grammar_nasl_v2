#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update poppler-4638.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(28178);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 20:36:48 $");

  script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");

  script_name(english:"openSUSE 10 Security Update : poppler (poppler-4638)");
  script_summary(english:"Check for the poppler-4638 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow in the xpdf code contained in poppler could be
exploited by attackers to potentially execute arbitrary code
(CVE-2007-4352, CVE-2007-5392, CVE-2007-5393)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected poppler packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-qt4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:poppler-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/12");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"poppler-0.4.4-19.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"poppler-devel-0.4.4-19.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"poppler-glib-0.4.4-19.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"poppler-qt-0.4.4-19.15") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"poppler-0.5.4-33.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"poppler-devel-0.5.4-33.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"poppler-glib-0.5.4-33.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"poppler-qt-0.5.4-33.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"poppler-tools-0.5.4-33.5") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"poppler-0.5.4-101.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"poppler-devel-0.5.4-101.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"poppler-glib-0.5.4-101.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"poppler-qt-0.5.4-101.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"poppler-qt4-0.5.4-101.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"poppler-tools-0.5.4-101.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "poppler / poppler-devel / poppler-glib / poppler-qt / poppler-tools / etc");
}
