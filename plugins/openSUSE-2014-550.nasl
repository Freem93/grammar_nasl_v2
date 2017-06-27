#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-550.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(77803);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/09/26 10:38:38 $");

  script_cve_id("CVE-2014-3168", "CVE-2014-3169", "CVE-2014-3170", "CVE-2014-3171", "CVE-2014-3172", "CVE-2014-3173", "CVE-2014-3174", "CVE-2014-3175", "CVE-2014-3176", "CVE-2014-3177");
  script_bugtraq_id(69398, 69400, 69401, 69403, 69404, 69405, 69406, 69407);

  script_name(english:"openSUSE Security Update : chromium (openSUSE-SU-2014:1151-1)");
  script_summary(english:"Check for the openSUSE-2014-550 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was updated to 37.0.2062.94 containing security Fixes
(bnc#893720).

A full list of changes is available in the log :

https://chromium.googlesource.com/chromium/src/+log/36.0.1985.0..37.0.
2062.0?pretty=full

This update includes 50 security fixes. Below, we highlight fixes that
were either contributed by external researchers or particularly
interesting. Please see the Chromium security page for more
information.

Critical CVE-2014-3176, CVE-2014-3177: A special reward to
lokihardt@asrt for a combination of bugs in V8, IPC, sync, and
extensions that can lead to remote code execution outside of the
sandbox.

High CVE-2014-3168: Use-after-free in SVG. Credit to cloudfuzzer. High
CVE-2014-3169: Use-after-free in DOM. Credit to Andrzej Dyjak. High
CVE-2014-3170: Extension permission dialog spoofing. Credit to Rob Wu.
High CVE-2014-3171: Use-after-free in bindings. Credit to cloudfuzzer.
Medium CVE-2014-3172: Issue related to extension debugging. Credit to
Eli Grey. Medium CVE-2014-3173: Uninitialized memory read in WebGL.
Credit to jmuizelaar. Medium CVE-2014-3174: Uninitialized memory read
in Web Audio. Credit to Atte Kettunen from OUSPG.

We would also like to thank Collin Payne, Christoph Diehl, Sebastian
Mauer, Atte Kettunen, and cloudfuzzer for working with us during the
development cycle to prevent security bugs from ever reaching the
stable channel. $8000 in additional rewards were issued.

As usual, our ongoing internal security work responsible for a wide
range of fixes: CVE-2014-3175: Various fixes from internal audits,
fuzzing and other initiatives (Chrome 37).

Many of the above bugs were detected using AddressSanitizer."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-09/msg00033.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=893720"
  );
  # https://chromium.googlesource.com/chromium/src/+log/36.0.1985.0..37.0.2062.0?pretty=full
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c4b20f6"
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/23");
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

if ( rpm_check(release:"SUSE12.3", reference:"chromedriver-37.0.2062.94-1.55.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromedriver-debuginfo-37.0.2062.94-1.55.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-37.0.2062.94-1.55.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-debuginfo-37.0.2062.94-1.55.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-debugsource-37.0.2062.94-1.55.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-desktop-gnome-37.0.2062.94-1.55.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-desktop-kde-37.0.2062.94-1.55.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-ffmpegsumo-37.0.2062.94-1.55.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-ffmpegsumo-debuginfo-37.0.2062.94-1.55.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-37.0.2062.94-50.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-debuginfo-37.0.2062.94-50.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-37.0.2062.94-50.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debuginfo-37.0.2062.94-50.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debugsource-37.0.2062.94-50.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-gnome-37.0.2062.94-50.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-kde-37.0.2062.94-50.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-37.0.2062.94-50.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-debuginfo-37.0.2062.94-50.1") ) flag++;

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
