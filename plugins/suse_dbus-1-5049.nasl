#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update dbus-1-5049.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(31395);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/06/13 20:06:06 $");

  script_cve_id("CVE-2008-0595");

  script_name(english:"openSUSE 10 Security Update : dbus-1 (dbus-1-5049)");
  script_summary(english:"Check for the dbus-1-5049 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of dbus-1 fixes a vulnerability caused by applying the
policies incorrectly. (CVE-2008-0595)"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dbus-1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-glib-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-qt-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-qt3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-qt3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-qt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/27");
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

if ( rpm_check(release:"SUSE10.1", reference:"dbus-1-0.60-33.17.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"dbus-1-devel-0.60-33.17.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"dbus-1-glib-0.60-33.17.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"dbus-1-gtk-0.60-33.20.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"dbus-1-java-0.60-33.20.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"dbus-1-mono-0.60-33.20.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"dbus-1-python-0.60-33.20.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"dbus-1-qt-0.60-33.20.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"dbus-1-qt-devel-0.60-33.20.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"dbus-1-qt3-0.60-33.20.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"dbus-1-qt3-devel-0.60-33.20.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"dbus-1-x11-0.60-33.20.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"dbus-1-32bit-0.60-33.17.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"dbus-1-glib-32bit-0.60-33.17.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"dbus-1-qt-32bit-0.60-33.20.3") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"dbus-1-qt3-32bit-0.60-33.20.3") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"dbus-1-1.0.0-9") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"dbus-1-devel-1.0.0-9") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"dbus-1-glib-0.71-27") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"dbus-1-glib-devel-0.71-27") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"dbus-1-mono-0.63-29") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"dbus-1-python-0.71-29") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"dbus-1-qt3-0.62-39") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"dbus-1-qt3-devel-0.62-39") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"dbus-1-x11-1.0.0-9") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"dbus-1-32bit-1.0.0-9") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"dbus-1-glib-32bit-0.71-27") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"dbus-1-qt3-32bit-0.62-39") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"dbus-1-1.0.2-59.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"dbus-1-devel-1.0.2-59.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"dbus-1-glib-0.74-25.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"dbus-1-glib-devel-0.74-25.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"dbus-1-mono-0.63-90.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"dbus-1-python-0.82.0-28.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"dbus-1-qt3-0.62-110.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"dbus-1-qt3-devel-0.62-110.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"dbus-1-x11-1.0.2-67.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"dbus-1-32bit-1.0.2-59.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"dbus-1-glib-32bit-0.74-25.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"dbus-1-qt3-32bit-0.62-110.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dbus-1");
}
