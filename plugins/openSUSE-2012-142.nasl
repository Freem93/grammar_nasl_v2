#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-142.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74563);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2011-3015", "CVE-2011-3016", "CVE-2011-3017", "CVE-2011-3018", "CVE-2011-3019", "CVE-2011-3020", "CVE-2011-3021", "CVE-2011-3022", "CVE-2011-3023", "CVE-2011-3024", "CVE-2011-3025", "CVE-2011-3026", "CVE-2011-3027", "CVE-2011-3953", "CVE-2011-3954", "CVE-2011-3955", "CVE-2011-3956", "CVE-2011-3957", "CVE-2011-3958", "CVE-2011-3959", "CVE-2011-3960", "CVE-2011-3961", "CVE-2011-3962", "CVE-2011-3963", "CVE-2011-3964", "CVE-2011-3965", "CVE-2011-3966", "CVE-2011-3967", "CVE-2011-3968", "CVE-2011-3969", "CVE-2011-3970", "CVE-2011-3971", "CVE-2011-3972");

  script_name(english:"openSUSE Security Update : chromium / v8 (openSUSE-2012-142)");
  script_summary(english:"Check for the openSUSE-2012-142 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium version 19.0.1046 and v8 version 3.9.7.0 fix several security
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747327"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium / v8 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/28");
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

if ( rpm_check(release:"SUSE12.1", reference:"chromium-19.0.1046.0-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debuginfo-19.0.1046.0-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debugsource-19.0.1046.0-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-gnome-19.0.1046.0-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-kde-19.0.1046.0-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-19.0.1046.0-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-debuginfo-19.0.1046.0-1.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libv8-3-3.9.7.0-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libv8-3-debuginfo-3.9.7.0-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"v8-debugsource-3.9.7.0-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"v8-devel-3.9.7.0-1.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"v8-private-headers-devel-3.9.7.0-1.13.1") ) flag++;

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
