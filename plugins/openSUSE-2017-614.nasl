#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-614.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(100395);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/25 13:29:27 $");

  script_cve_id("CVE-2016-9401");

  script_name(english:"openSUSE Security Update : bash (openSUSE-2017-614)");
  script_summary(english:"Check for the openSUSE-2017-614 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for bash fixes an issue that could lead to syntax errors
when parsing scripts that use expr(1) inside loops.

Additionally, the popd build-in now ensures that the normalized stack
offset is within bounds before trying to free that stack entry. This
fixes a segmentation fault.

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1035371"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bash packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bash-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bash-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bash-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bash-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bash-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bash-loadables");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bash-loadables-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreadline6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreadline6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreadline6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libreadline6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:readline-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:readline-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/25");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"bash-4.3-80.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bash-debuginfo-4.3-80.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bash-debugsource-4.3-80.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bash-devel-4.3-80.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bash-lang-4.3-80.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bash-loadables-4.3-80.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"bash-loadables-debuginfo-4.3-80.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreadline6-6.3-80.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libreadline6-debuginfo-6.3-80.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"readline-devel-6.3-80.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"bash-debuginfo-32bit-4.3-80.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreadline6-32bit-6.3-80.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"libreadline6-debuginfo-32bit-6.3-80.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"readline-devel-32bit-6.3-80.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bash / bash-debuginfo-32bit / bash-debuginfo / bash-debugsource / etc");
}
