#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update fileshareset-4454.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27217);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/22 20:32:45 $");

  script_cve_id("CVE-2007-4224", "CVE-2007-4569");

  script_name(english:"openSUSE 10 Security Update : fileshareset (fileshareset-4454)");
  script_summary(english:"Check for the fileshareset-4454 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Users could log in as root without having to enter the password if
auto login was enabled and if kdm was configured to require the root
passwort to shutdown the system (CVE-2007-4569).

JavaScript code could modify the URL in the address bar to make the
currently displayed website appear to come from a different site
(CVE-2007-4224)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected fileshareset packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_cwe_id(59, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:fileshareset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3-beagle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3-kdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3-ksysguardd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3-nsplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3-nsplugin64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdebase3-session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs3-arts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs3-arts-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdelibs3-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"fileshareset-2.0-84.57") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kdebase3-3.5.1-69.58") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kdebase3-devel-3.5.1-69.58") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kdebase3-extra-3.5.1-69.58") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kdebase3-kdm-3.5.1-69.58") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kdebase3-ksysguardd-3.5.1-69.58") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kdebase3-nsplugin-3.5.1-69.58") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kdebase3-samba-3.5.1-69.58") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kdebase3-session-3.5.1-69.58") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kdelibs3-3.5.1-49.39") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kdelibs3-arts-3.5.1-49.39") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kdelibs3-devel-3.5.1-49.39") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"kdebase3-32bit-3.5.1-69.58") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"kdebase3-nsplugin64-3.5.1-69.58") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"kdelibs3-32bit-3.5.1-49.39") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"kdelibs3-arts-32bit-3.5.1-49.39") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"fileshareset-2.0-242.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kdebase3-3.5.5-102.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kdebase3-beagle-3.5.5-102.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kdebase3-devel-3.5.5-102.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kdebase3-extra-3.5.5-102.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kdebase3-kdm-3.5.5-102.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kdebase3-ksysguardd-3.5.5-102.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kdebase3-nsplugin-3.5.5-102.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kdebase3-samba-3.5.5-102.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kdebase3-session-3.5.5-102.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kdelibs3-3.5.5-45.6") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kdelibs3-arts-3.5.5-45.6") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"kdelibs3-devel-3.5.5-45.6") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"kdebase3-32bit-3.5.5-102.8") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"kdelibs3-32bit-3.5.5-45.6") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"kdelibs3-arts-32bit-3.5.5-45.6") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fileshareset / kdebase3 / kdebase3-32bit / kdebase3-devel / etc");
}
