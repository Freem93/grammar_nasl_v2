#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-639.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86336);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/10/13 14:27:27 $");

  script_cve_id("CVE-2014-9745", "CVE-2014-9747");

  script_name(english:"openSUSE Security Update : freetype2 (openSUSE-2015-639)");
  script_summary(english:"Check for the openSUSE-2015-639 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of the freetype2 library fixes two security issues.

These security issues were fixed :

  - CVE-2014-9745: Infinite loop in parse_encoding in
    t1load.c (bsc#945849)

  - CVE-2014-9747: Use of uninitialized memory in
    ps_parser_load_field, t42_parse_font_matrix and
    t1_parse_font_matrix (bsc#947966)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=945849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=947966"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freetype2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freetype2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freetype2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:freetype2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ft2demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ft2demos-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ft2demos-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreetype6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreetype6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreetype6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreetype6-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"freetype2-debugsource-2.5.0.1-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"freetype2-devel-2.5.0.1-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ft2demos-2.5.0-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ft2demos-debuginfo-2.5.0-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ft2demos-debugsource-2.5.0-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfreetype6-2.5.0.1-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libfreetype6-debuginfo-2.5.0.1-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"freetype2-devel-32bit-2.5.0.1-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfreetype6-32bit-2.5.0.1-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libfreetype6-debuginfo-32bit-2.5.0.1-2.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype2-debugsource / freetype2-devel / freetype2-devel-32bit / etc");
}
