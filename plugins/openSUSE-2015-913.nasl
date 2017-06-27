#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-913.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(87517);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/21 14:44:24 $");

  script_cve_id("CVE-2015-1804");

  script_name(english:"openSUSE Security Update : libXfont (openSUSE-2015-913)");
  script_summary(english:"Check for the openSUSE-2015-913 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libXfont fixes the following issue :

  - A negative DWIDTH is legal. This was broken by the
    security fix for CVE-2015-1804. (boo#958383)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=958383"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libXfont packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"libXfont-debugsource-1.4.6-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libXfont-devel-1.4.6-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libXfont1-1.4.6-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libXfont1-debuginfo-1.4.6-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libXfont-devel-32bit-1.4.6-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libXfont1-32bit-1.4.6-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libXfont1-debuginfo-32bit-1.4.6-2.15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libXfont-debugsource-1.5.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libXfont-devel-1.5.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libXfont1-1.5.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libXfont1-debuginfo-1.5.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libXfont-devel-32bit-1.5.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libXfont1-32bit-1.5.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libXfont1-debuginfo-32bit-1.5.0-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXfont-debugsource-1.5.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXfont-devel-1.5.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXfont1-1.5.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"libXfont1-debuginfo-1.5.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXfont-devel-32bit-1.5.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXfont1-32bit-1.5.1-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"libXfont1-debuginfo-32bit-1.5.1-7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libXfont-debugsource / libXfont-devel / libXfont-devel-32bit / etc");
}
