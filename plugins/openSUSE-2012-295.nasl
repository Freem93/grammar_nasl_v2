#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-295.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74634);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/20 14:21:42 $");

  script_cve_id("CVE-2011-3083", "CVE-2011-3084", "CVE-2011-3085", "CVE-2011-3086", "CVE-2011-3087", "CVE-2011-3088", "CVE-2011-3089", "CVE-2011-3090", "CVE-2011-3091", "CVE-2011-3092", "CVE-2011-3093", "CVE-2011-3094", "CVE-2011-3095", "CVE-2011-3096", "CVE-2011-3098", "CVE-2011-3100", "CVE-2011-3101", "CVE-2011-3102");
  script_osvdb_id(81945, 81946, 81947, 81948, 81949, 81950, 81951, 81952, 81953, 81954, 81955, 81956, 81957, 81958, 81960, 81962, 81963, 81964);

  script_name(english:"openSUSE Security Update : chromium / v8 (openSUSE-SU-2012:0656-1)");
  script_summary(english:"Check for the openSUSE-2012-295 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium update to 21.0.1145

  - Fixed several issues around audio not playing with
    videos

  - Crash Fixes

  - Improvements to trackpad on Cr-48

  - Security Fixes (bnc#762481)

  - CVE-2011-3083: Browser crash with video + FTP

  - CVE-2011-3084: Load links from internal pages in their
    own process.

  - CVE-2011-3085: UI corruption with long autofilled values

  - CVE-2011-3086: Use-after-free with style element.

  - CVE-2011-3087: Incorrect window navigation

  - CVE-2011-3088: Out-of-bounds read in hairline drawing

  - CVE-2011-3089: Use-after-free in table handling.

  - CVE-2011-3090: Race condition with workers.

  - CVE-2011-3091: Use-after-free with indexed DB

  - CVE-2011-3092: Invalid write in v8 regex

  - CVE-2011-3093: Out-of-bounds read in glyph handling

  - CVE-2011-3094: Out-of-bounds read in Tibetan handling

  - CVE-2011-3095: Out-of-bounds write in OGG container.

  - CVE-2011-3096: Use-after-free in GTK omnibox handling.

  - CVE-2011-3098: Bad search path for Windows Media Player
    plug-in

  - CVE-2011-3100: Out-of-bounds read drawing dash paths.

  - CVE-2011-3101: Work around Linux Nvidia driver bug

  - CVE-2011-3102: Off-by-one out-of-bounds write in libxml."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-05/msg00040.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762481"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium / v8 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE12.1", reference:"chromium-21.0.1145.0-1.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debuginfo-21.0.1145.0-1.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debugsource-21.0.1145.0-1.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-gnome-21.0.1145.0-1.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-kde-21.0.1145.0-1.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-21.0.1145.0-1.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-debuginfo-21.0.1145.0-1.23.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libv8-3-3.11.3.0-1.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libv8-3-debuginfo-3.11.3.0-1.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"v8-debugsource-3.11.3.0-1.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"v8-devel-3.11.3.0-1.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"v8-private-headers-devel-3.11.3.0-1.27.1") ) flag++;

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
