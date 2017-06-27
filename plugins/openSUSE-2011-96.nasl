#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2011-96.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74541);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2011-3439");

  script_name(english:"openSUSE Security Update : freetype2 (openSUSE-2011-96)");
  script_summary(english:"Check for the openSUSE-2011-96 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"FreeType allowed remote attackers to execute arbitrary code or cause a
denial of service (memory corruption) via a crafted font.
(CVE-2011-3439, bnc#730124)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=730124"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freetype2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/20");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"freetype2-debugsource-2.4.7-3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"freetype2-devel-2.4.7-3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"ft2demos-2.4.7-3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"ft2demos-debuginfo-2.4.7-3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"ft2demos-debugsource-2.4.7-3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libfreetype6-2.4.7-3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libfreetype6-debuginfo-2.4.7-3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"freetype2-devel-32bit-2.4.7-3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfreetype6-32bit-2.4.7-3.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfreetype6-debuginfo-32bit-2.4.7-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freetype2-debugsource / libfreetype6-32bit / libfreetype6-debuginfo / etc");
}
