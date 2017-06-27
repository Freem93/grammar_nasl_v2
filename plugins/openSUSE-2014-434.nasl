#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-434.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(76182);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/03 10:38:32 $");

  script_cve_id("CVE-2014-3477");
  script_bugtraq_id(67986);

  script_name(english:"openSUSE Security Update : dbus-1 (openSUSE-SU-2014:0821-1)");
  script_summary(english:"Check for the openSUSE-2014-434 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:"dbus-1 was updated to fix a possible DoS (CVE-2014-3477)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-06/msg00042.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=881137"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dbus-1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dbus-1-x11-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdbus-1-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdbus-1-3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdbus-1-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libdbus-1-3-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/23");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"dbus-1-1.6.8-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"dbus-1-debuginfo-1.6.8-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"dbus-1-debugsource-1.6.8-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"dbus-1-devel-1.6.8-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"dbus-1-x11-1.6.8-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"dbus-1-x11-debuginfo-1.6.8-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"dbus-1-x11-debugsource-1.6.8-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libdbus-1-3-1.6.8-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libdbus-1-3-debuginfo-1.6.8-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"dbus-1-32bit-1.6.8-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"dbus-1-debuginfo-32bit-1.6.8-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"dbus-1-devel-32bit-1.6.8-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libdbus-1-3-32bit-1.6.8-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libdbus-1-3-debuginfo-32bit-1.6.8-2.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dbus-1-1.7.4-4.12.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dbus-1-debuginfo-1.7.4-4.12.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dbus-1-debugsource-1.7.4-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dbus-1-devel-1.7.4-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dbus-1-x11-1.7.4-4.12.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dbus-1-x11-debuginfo-1.7.4-4.12.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"dbus-1-x11-debugsource-1.7.4-4.12.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdbus-1-3-1.7.4-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libdbus-1-3-debuginfo-1.7.4-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"dbus-1-debuginfo-32bit-1.7.4-4.12.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"dbus-1-devel-32bit-1.7.4-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdbus-1-3-32bit-1.7.4-4.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libdbus-1-3-debuginfo-32bit-1.7.4-4.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dbus-1");
}
