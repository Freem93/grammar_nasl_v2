#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-272.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74622);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2011-3078", "CVE-2011-3079", "CVE-2011-3080", "CVE-2011-3081", "CVE-2012-1521");

  script_name(english:"openSUSE Security Update : chromium / v8 (openSUSE-SU-2012:0613-1)");
  script_summary(english:"Check for the openSUSE-2012-272 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium version 20.0.1128 fixes several security issues :

  - CVE-2011-3078: Use after free in floats handling.

  - CVE-2012-1521: Use after free in xml parser.

  - CVE-2011-3079: IPC validation failure.

  - CVE-2011-3080: Race condition in sandbox IPC

  - CVE-2011-3081: Use after free in floats handling."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-05/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=759381"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=760264"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium / v8 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-suid-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-suid-helper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libv8-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libv8-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v8-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v8-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:v8-private-headers-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/10");
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

if ( rpm_check(release:"SUSE12.1", reference:"chromium-20.0.1128.0-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debuginfo-20.0.1128.0-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debugsource-20.0.1128.0-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-gnome-20.0.1128.0-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-kde-20.0.1128.0-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-20.0.1128.0-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-debuginfo-20.0.1128.0-1.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libv8-3-3.10.8.1-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libv8-3-debuginfo-3.10.8.1-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"v8-debugsource-3.10.8.1-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"v8-devel-3.10.8.1-1.24.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"v8-private-headers-devel-3.10.8.1-1.24.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromium / chromium-debuginfo / chromium-debugsource / etc");
}
