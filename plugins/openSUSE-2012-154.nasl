#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-154.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74566);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/10/29 10:42:05 $");

  script_cve_id("CVE-2011-3153", "CVE-2012-1111");
  script_osvdb_id(77176, 80076);

  script_name(english:"openSUSE Security Update : lightdm (openSUSE-SU-2012:0354-1)");
  script_summary(english:"Check for the openSUSE-2012-154 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - update to version 1.0.9

  - stop file descriptors leaking into the session processes
    (bnc#745339, lp#927060, CVE-2012-1111)

  - fix compilation against gthread

  - change session directory once user permissions are set
    so it works on NFS filesystems that don't allow root to
    access files

  - fix object cleanup on exit

  - fix lightdm --debug not working on newer GLib

  - drop privileges when reading ~/.dmrc (CVE-2011-3153)

  - fix crash calling lightdm_get_layout

  - drop lightdm-CVE-2011-3153.patch which has been included
    upstream"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-03/msg00019.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745339"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lightdm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblightdm-gobject-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblightdm-gobject-1-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblightdm-qt-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblightdm-qt-1-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-gtk-greeter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-gtk-greeter-branding-openSUSE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-gtk-greeter-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-gtk-greeter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-qt-greeter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lightdm-qt-greeter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/08");
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

if ( rpm_check(release:"SUSE12.1", reference:"liblightdm-gobject-1-0-1.0.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"liblightdm-gobject-1-0-debuginfo-1.0.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"liblightdm-qt-1-0-1.0.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"liblightdm-qt-1-0-debuginfo-1.0.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-1.0.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-debuginfo-1.0.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-debugsource-1.0.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-gobject-devel-1.0.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-gtk-greeter-1.0.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-gtk-greeter-branding-openSUSE-12.1-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-gtk-greeter-branding-upstream-1.0.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-gtk-greeter-debuginfo-1.0.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-lang-1.0.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-qt-devel-1.0.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-qt-greeter-1.0.9-8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"lightdm-qt-greeter-debuginfo-1.0.9-8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lightdm-gtk-greeter-branding-openSUSE / liblightdm-gobject-1-0 / etc");
}
