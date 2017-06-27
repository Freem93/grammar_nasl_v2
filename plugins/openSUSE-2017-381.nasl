#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-381.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(99016);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/28 13:31:43 $");

  script_cve_id("CVE-2017-6503", "CVE-2017-6504");

  script_name(english:"openSUSE Security Update : qbittorrent (openSUSE-2017-381)");
  script_summary(english:"Check for the openSUSE-2017-381 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to qbittorrent 3.3.11 fixes the security issues and bugs.

The following vulnerabilities were fixed :

  - CVE-2017-6504: WebUI did not set the X-Frame-Options
    header (bsc#1028073)

  - CVE-2017-6503: WebUI did not escape many values,
    allowing for XSS (bsc#1028072)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1028073"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected qbittorrent packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qbittorrent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qbittorrent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qbittorrent-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qbittorrent-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qbittorrent-nox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"qbittorrent-3.3.11-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qbittorrent-debuginfo-3.3.11-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qbittorrent-debugsource-3.3.11-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qbittorrent-nox-3.3.11-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"qbittorrent-nox-debuginfo-3.3.11-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qbittorrent-3.3.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qbittorrent-debuginfo-3.3.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qbittorrent-debugsource-3.3.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qbittorrent-nox-3.3.11-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"qbittorrent-nox-debuginfo-3.3.11-2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qbittorrent / qbittorrent-debuginfo / qbittorrent-debugsource / etc");
}
