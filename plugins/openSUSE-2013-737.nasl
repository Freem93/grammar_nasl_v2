#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-737.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75158);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-4288");
  script_bugtraq_id(62511);
  script_osvdb_id(97511);

  script_name(english:"openSUSE Security Update : systemd (openSUSE-SU-2013:1528-1)");
  script_summary(english:"Check for the openSUSE-2013-737 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This systemd update fixes several security and non-security issues.

  - polkit-Avoid-race-condition-in-scraping-proc.patch:
    VUL-0: polkit: process subject race condition
    (bnc#836932) CVE-2013-4288.

  - Don't use a trigger to create symlink for sysctl.conf,
    always run the test on %post (bnc#840864).

  - Move symlink migration trigger to post (bnc#821800).

  - Add systemd-fix-crash-listing-session-files.patch
    (bnc#840055)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-10/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=836932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=840055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=840864"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected systemd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgudev-1_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgudev-1_0-0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgudev-1_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgudev-1_0-0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgudev-1_0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev-mini1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libudev1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-analyze");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-analyze");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-mini-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:systemd-sysvinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-GUdev-1_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-mini");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev-mini-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/27");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"libgudev-1_0-0-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgudev-1_0-0-debuginfo-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgudev-1_0-devel-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libudev-devel-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libudev-mini-devel-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libudev-mini1-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libudev-mini1-debuginfo-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libudev1-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libudev1-debuginfo-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"systemd-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"systemd-analyze-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"systemd-debuginfo-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"systemd-debugsource-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"systemd-devel-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"systemd-logger-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"systemd-mini-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"systemd-mini-analyze-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"systemd-mini-debuginfo-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"systemd-mini-debugsource-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"systemd-mini-devel-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"systemd-mini-sysvinit-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"systemd-sysvinit-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"typelib-1_0-GUdev-1_0-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"udev-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"udev-debuginfo-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"udev-mini-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"udev-mini-debuginfo-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libgudev-1_0-0-32bit-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libgudev-1_0-0-debuginfo-32bit-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libudev1-32bit-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libudev1-debuginfo-32bit-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"systemd-32bit-195-13.45.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"systemd-debuginfo-32bit-195-13.45.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemd");
}
