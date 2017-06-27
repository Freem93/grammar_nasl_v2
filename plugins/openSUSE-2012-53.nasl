#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-53.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74731);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_name(english:"openSUSE Security Update : NetworkManager-gnome (openSUSE-2012-53)");
  script_summary(english:"Check for the openSUSE-2012-53 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:"Also enable certificate checks for EAP-TLS"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=574266"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected NetworkManager-gnome packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager-gnome-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:NetworkManager-gnome-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnm-gtk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnm-gtk0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnm-gtk0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/11");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"NetworkManager-gnome-0.9.1.90-3.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"NetworkManager-gnome-debuginfo-0.9.1.90-3.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"NetworkManager-gnome-debugsource-0.9.1.90-3.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"NetworkManager-gnome-lang-0.9.1.90-3.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libnm-gtk-devel-0.9.1.90-3.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libnm-gtk0-0.9.1.90-3.15.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libnm-gtk0-debuginfo-0.9.1.90-3.15.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "NetworkManager-gnome / NetworkManager-gnome-debuginfo / etc");
}
