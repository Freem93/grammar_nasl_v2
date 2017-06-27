#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update dbus-1-5972.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(35955);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/06/13 20:06:06 $");

  script_cve_id("CVE-2008-4311");

  script_name(english:"openSUSE 10 Security Update : dbus-1 (dbus-1-5972)");
  script_summary(english:"Check for the dbus-1-5972 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The dbus package used a too permissive configuration. Therefore
intended access control for some services was not applied
(CVE-2008-4311).

The new configuration denies access by default. Some dbus services may
break due to this setting and need an updated configuration as well."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dbus-1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-glib-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-qt3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-qt3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-qt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE10.3", reference:"dbus-1-1.0.2-59.8") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"dbus-1-devel-1.0.2-59.8") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"dbus-1-glib-0.74-25.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"dbus-1-glib-devel-0.74-25.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"dbus-1-mono-0.63-90.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"dbus-1-python-0.82.0-28.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"dbus-1-python-devel-0.82.0-28.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"dbus-1-qt3-0.62-110.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"dbus-1-qt3-devel-0.62-110.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"dbus-1-x11-1.0.2-67.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"dbus-1-32bit-1.0.2-59.8") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"dbus-1-glib-32bit-0.74-25.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"dbus-1-qt3-32bit-0.62-110.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dbus-1 / dbus-1-32bit / dbus-1-devel / dbus-1-glib / etc");
}
