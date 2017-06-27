#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update gnome-screensaver-1973.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(44622);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/06/13 20:00:35 $");

  script_cve_id("CVE-2010-0285", "CVE-2010-0414", "CVE-2010-0422");

  script_name(english:"openSUSE Security Update : gnome-screensaver (gnome-screensaver-1973)");
  script_summary(english:"Check for the gnome-screensaver-1973 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"gnome-screensaver was updated to the stable release 2.28.3, fixing
various bugs and security issues.

Following security issues have been fixed: When resuming a system
gnome-screensaver does not lock external displays that got connected
while the system was suspended (CVE-2010-0285: CVSS v2 Base Score:
5.6).

Additionally another bug in gnome-screensaver was fixed that allowed
bypassing the unlock dialog by using a removable monitor.
(CVE-2010-0414: CVSS v2 Base Score: 6.2)

Pressing 'return' repeatedly caused a X error which terminated the
lock and so allowed local users to access the underlying session. (no
CVE yet)

CVE-2010-0422: gnome-screensaver can lose its keyboard grab when
locked, exposing the system to intrusion by adding and removing
monitors."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=550695"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnome-screensaver packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-screensaver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gnome-screensaver-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE11.2", reference:"gnome-screensaver-2.28.3-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"gnome-screensaver-lang-2.28.3-0.1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnome-screensaver");
}
