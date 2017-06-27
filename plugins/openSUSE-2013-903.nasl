#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-903.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75212);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-2925", "CVE-2013-2926", "CVE-2013-2927", "CVE-2013-2928", "CVE-2013-2931", "CVE-2013-6621", "CVE-2013-6622", "CVE-2013-6623", "CVE-2013-6624", "CVE-2013-6625", "CVE-2013-6626", "CVE-2013-6627", "CVE-2013-6628", "CVE-2013-6629", "CVE-2013-6630", "CVE-2013-6631", "CVE-2013-6632");
  script_bugtraq_id(63024, 63025, 63026, 63028, 63667, 63669, 63670, 63671, 63672, 63673, 63674, 63675, 63676, 63677, 63678, 63679, 63729);

  script_name(english:"openSUSE Security Update : chromium (openSUSE-SU-2013:1776-1)");
  script_summary(english:"Check for the openSUSE-2013-903 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security and bugfix update to Chromium 31.0.1650.57

  - Update to Chromium 31.0.1650.57 :

  - Security Fixes :

  - CVE-2013-6632: Multiple memory corruption issues.

  - Update to Chromium 31.0.1650.48 Stable Channel update :

  - Security fixes :

  - CVE-2013-6621: Use after free related to speech input
    elements..

  - CVE-2013-6622: Use after free related to media elements. 

  - CVE-2013-6623: Out of bounds read in SVG.

  - CVE-2013-6624: Use after free related to
    &ldquo;id&rdquo; attribute strings.

  - CVE-2013-6625: Use after free in DOM ranges.

  - CVE-2013-6626: Address bar spoofing related to
    interstitial warnings.

  - CVE-2013-6627: Out of bounds read in HTTP parsing.

  - CVE-2013-6628: Issue with certificates not being checked
    during TLS renegotiation.

  - CVE-2013-2931: Various fixes from internal audits,
    fuzzing and other initiatives.

  - CVE-2013-6629: Read of uninitialized memory in libjpeg
    and libjpeg-turbo.

  - CVE-2013-6630: Read of uninitialized memory in
    libjpeg-turbo.

  - CVE-2013-6631: Use after free in libjingle.

  - Stable Channel update: fix build for 32bit systems

  - Update to Chromium 30.0.1599.101

  - Security Fixes :

  + CVE-2013-2925: Use after free in XHR

  + CVE-2013-2926: Use after free in editing

  + CVE-2013-2927: Use after free in forms.

  + CVE-2013-2928: Various fixes from internal audits,
    fuzzing and other initiatives.

  - Enable ARM build for Chromium."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-11/msg00107.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=849715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=850430"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-suid-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-suid-helper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/20");
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

if ( rpm_check(release:"SUSE12.3", reference:"chromedriver-31.0.1650.57-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromedriver-debuginfo-31.0.1650.57-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-31.0.1650.57-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-debuginfo-31.0.1650.57-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-debugsource-31.0.1650.57-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-desktop-gnome-31.0.1650.57-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-desktop-kde-31.0.1650.57-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-ffmpegsumo-31.0.1650.57-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-ffmpegsumo-debuginfo-31.0.1650.57-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-suid-helper-31.0.1650.57-1.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-suid-helper-debuginfo-31.0.1650.57-1.17.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromium");
}
