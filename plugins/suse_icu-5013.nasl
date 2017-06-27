#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update icu-5013.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(31399);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/06/13 20:11:35 $");

  script_cve_id("CVE-2007-4770", "CVE-2007-4771");

  script_name(english:"openSUSE 10 Security Update : icu (icu-5013)");
  script_summary(english:"Check for the icu-5013 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Certain regular expressions could crash the ICU library
(CVE-2007-4770, CVE-2007-4771)."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected icu packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:icu-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libicu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libicu-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libicu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libicu-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE10.1", reference:"icu-3.4-16.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"icu-data-3.4-16.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"libicu-3.4-16.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"libicu-devel-3.4-16.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"libicu-32bit-3.4-16.6") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"libicu-devel-32bit-3.4-16.6") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"icu-3.4-36") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"icu-data-3.4-36") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"libicu-3.4-36") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"libicu-devel-3.4-36") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"libicu-32bit-3.4-36") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"libicu-devel-32bit-3.4-36") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"icu-3.6-13.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"icu-data-3.6-13.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libicu-3.6-13.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"libicu-devel-3.6-13.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"libicu-32bit-3.6-13.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"libicu-devel-32bit-3.6-13.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icu / icu-data / libicu / libicu-32bit / libicu-devel / etc");
}
