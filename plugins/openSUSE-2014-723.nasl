#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-723.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(79616);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/28 15:03:08 $");

  script_cve_id("CVE-2014-3710");

  script_name(english:"openSUSE Security Update : file (openSUSE-SU-2014:1516-1)");
  script_summary(english:"Check for the openSUSE-2014-723 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"file was updated to fix one security issue.

This security issue was fixed :

  - Out-of-bounds read in elf note headers (CVE-2014-3710)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-11/msg00113.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=902367"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected file packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:file-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:file-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:file-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:file-magic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmagic-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmagic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmagic1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmagic1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmagic1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-magic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/28");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"file-5.11-12.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"file-debuginfo-5.11-12.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"file-debugsource-5.11-12.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"file-devel-5.11-12.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libmagic-data-5.11-12.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libmagic1-5.11-12.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libmagic1-debuginfo-5.11-12.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-magic-5.11-12.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libmagic1-32bit-5.11-12.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libmagic1-debuginfo-32bit-5.11-12.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"file-5.15-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"file-debuginfo-5.15-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"file-debugsource-5.15-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"file-devel-5.15-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"file-magic-5.15-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libmagic1-5.15-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libmagic1-debuginfo-5.15-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-magic-5.15-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libmagic1-32bit-5.15-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libmagic1-debuginfo-32bit-5.15-4.24.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"file-5.19-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"file-debuginfo-5.19-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"file-debugsource-5.19-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"file-devel-5.19-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"file-magic-5.19-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmagic1-5.19-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmagic1-debuginfo-5.19-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-magic-5.19-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmagic1-32bit-5.19-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmagic1-debuginfo-32bit-5.19-3.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "file / file-debuginfo / file-debugsource / file-devel / etc");
}
