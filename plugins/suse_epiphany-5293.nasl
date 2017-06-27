#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update epiphany-5293.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(33121);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/06/13 20:06:06 $");

  script_cve_id("CVE-2008-1380");

  script_name(english:"openSUSE 10 Security Update : epiphany (epiphany-5293)");
  script_summary(english:"Check for the epiphany-5293 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"mozilla-xulrunner181 was updated to version 1.8.1.14, fixing various
bugs including 1 security bug :

  + MFSA 2008-20/CVE-2008-1380: Crash in JavaScript garbage
    collector"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected epiphany packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:epiphany-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:epiphany-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner181");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner181-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner181-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner181-l10n");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/09");
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
if (release !~ "^(SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"epiphany-2.16.1-33") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"epiphany-devel-2.16.1-33") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"epiphany-extensions-2.16.1-33") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mozilla-xulrunner181-1.8.1.14-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mozilla-xulrunner181-devel-1.8.1.14-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"mozilla-xulrunner181-l10n-1.8.1.14-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"mozilla-xulrunner181-32bit-1.8.1.14-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"epiphany-2.20.0-8.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"epiphany-devel-2.20.0-8.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"epiphany-extensions-2.20.0-8.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mozilla-xulrunner181-1.8.1.14-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mozilla-xulrunner181-devel-1.8.1.14-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"mozilla-xulrunner181-l10n-1.8.1.14-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"mozilla-xulrunner181-32bit-1.8.1.14-0.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-xulrunner181");
}
