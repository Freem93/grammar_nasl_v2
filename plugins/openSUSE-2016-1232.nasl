#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1232.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94307);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/23 15:32:04 $");

  script_cve_id("CVE-2016-8605");

  script_name(english:"openSUSE Security Update : guile1 (openSUSE-2016-1232)");
  script_summary(english:"Check for the openSUSE-2016-1232 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for guile1 fixes the following issue :

  - CVE-2016-8605: Thread-unsafe umask modification
    (bsc#1004221)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004221"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected guile1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:guile1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:guile1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:guile1-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libguile-srfi-srfi-1-v-3-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libguile-srfi-srfi-1-v-3-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libguile-srfi-srfi-13-14-v-3-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libguile-srfi-srfi-13-14-v-3-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libguile-srfi-srfi-4-v-3-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libguile-srfi-srfi-4-v-3-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libguile-srfi-srfi-60-v-2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libguile-srfi-srfi-60-v-2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libguile1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libguile17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libguile17-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libguilereadline-v-17-17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libguilereadline-v-17-17-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"guile1-1.8.8-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"guile1-debuginfo-1.8.8-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"guile1-debugsource-1.8.8-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libguile-srfi-srfi-1-v-3-3-1.8.8-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libguile-srfi-srfi-1-v-3-3-debuginfo-1.8.8-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libguile-srfi-srfi-13-14-v-3-3-1.8.8-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libguile-srfi-srfi-13-14-v-3-3-debuginfo-1.8.8-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libguile-srfi-srfi-4-v-3-3-1.8.8-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libguile-srfi-srfi-4-v-3-3-debuginfo-1.8.8-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libguile-srfi-srfi-60-v-2-2-1.8.8-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libguile-srfi-srfi-60-v-2-2-debuginfo-1.8.8-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libguile1-devel-1.8.8-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libguile17-1.8.8-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libguile17-debuginfo-1.8.8-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libguilereadline-v-17-17-1.8.8-16.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libguilereadline-v-17-17-debuginfo-1.8.8-16.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "guile1 / guile1-debuginfo / guile1-debugsource / etc");
}
