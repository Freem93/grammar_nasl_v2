#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-182.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75275);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2013-6653", "CVE-2013-6654", "CVE-2013-6655", "CVE-2013-6656", "CVE-2013-6657", "CVE-2013-6658", "CVE-2013-6659", "CVE-2013-6660", "CVE-2013-6661");
  script_bugtraq_id(65699);

  script_name(english:"openSUSE Security Update : chromium (openSUSE-SU-2014:0327-1)");
  script_summary(english:"Check for the openSUSE-2014-182 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was updated to 33.0.1750.117 Stable channel update :

  - Security Fixes :

  - CVE-2013-6653: Use-after-free related to web contents

  - CVE-2013-6654: Bad cast in SVG

  - CVE-2013-6655: Use-after-free in layout

  - CVE-2013-6656: Information leak in XSS auditor

  - CVE-2013-6657: Information leak in XSS auditor

  - CVE-2013-6658: Use-after-free in layout

  - CVE-2013-6659: Issue with certificates validation in TLS
    handshake

  - CVE-2013-6660: Information leak in drag and drop

  - CVE-2013-6661: Various fixes from internal audits,
    fuzzing and other initiatives. Of these, seven are fixes
    for issues that could have allowed for sandbox escapes
    from compromised renderers.

  - Other :

  - Google Chrome Frame has been retired"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-03/msg00006.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/24");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"chromedriver-33.0.1750.117-1.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromedriver-debuginfo-33.0.1750.117-1.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-33.0.1750.117-1.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-debuginfo-33.0.1750.117-1.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-debugsource-33.0.1750.117-1.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-desktop-gnome-33.0.1750.117-1.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-desktop-kde-33.0.1750.117-1.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-ffmpegsumo-33.0.1750.117-1.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-ffmpegsumo-debuginfo-33.0.1750.117-1.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-suid-helper-33.0.1750.117-1.29.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-suid-helper-debuginfo-33.0.1750.117-1.29.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-33.0.1750.117-21.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-debuginfo-33.0.1750.117-21.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-33.0.1750.117-21.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debuginfo-33.0.1750.117-21.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debugsource-33.0.1750.117-21.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-gnome-33.0.1750.117-21.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-kde-33.0.1750.117-21.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-33.0.1750.117-21.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-debuginfo-33.0.1750.117-21.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-suid-helper-33.0.1750.117-21.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-suid-helper-debuginfo-33.0.1750.117-21.2") ) flag++;

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
