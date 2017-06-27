#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update dbus-1-glib-4237.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75462);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2010-1172");

  script_name(english:"openSUSE Security Update : dbus-1-glib (openSUSE-SU-2011:0300-1)");
  script_summary(english:"Check for the dbus-1-glib-4237 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"dbus-glib allowed local users to write properties that were exported
read-only via dbus (CVE-2010-1172)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-04/msg00020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=628607"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dbus-1-glib packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-glib-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-glib-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"dbus-1-glib-0.86-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"dbus-1-glib-devel-0.86-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"dbus-1-glib-32bit-0.86-2.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dbus-1-glib / dbus-1-glib-32bit / dbus-1-glib-devel");
}
