#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1235.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(94310);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/23 15:32:04 $");

  script_cve_id("CVE-2016-8605", "CVE-2016-8606");

  script_name(english:"openSUSE Security Update : guile (openSUSE-2016-1235)");
  script_summary(english:"Check for the openSUSE-2016-1235 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for guile fixes the following issues :

  - CVE-2016-8606: REPL server vulnerable to HTTP
    inter-protocol attacks (bsc#1004226).

  - CVE-2016-8605: Thread-unsafe umask modification
    (bsc#1004221)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004226"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected guile packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:guile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:guile-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:guile-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:guile-modules-2_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libguile-2_0-22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libguile-2_0-22-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libguilereadline-v-18-18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libguilereadline-v-18-18-debuginfo");
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

if ( rpm_check(release:"SUSE13.2", reference:"guile-2.0.11-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"guile-debuginfo-2.0.11-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"guile-debugsource-2.0.11-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"guile-devel-2.0.11-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"guile-modules-2_0-2.0.11-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libguile-2_0-22-2.0.11-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libguile-2_0-22-debuginfo-2.0.11-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libguilereadline-v-18-18-2.0.11-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libguilereadline-v-18-18-debuginfo-2.0.11-3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "guile / guile-debuginfo / guile-debugsource / guile-devel / etc");
}
