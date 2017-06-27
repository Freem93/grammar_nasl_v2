#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-817.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80277);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/12/29 13:38:34 $");

  script_cve_id("CVE-2014-8116", "CVE-2014-8117");

  script_name(english:"openSUSE Security Update : file (openSUSE-SU-2014:1720-1)");
  script_summary(english:"Check for the openSUSE-2014-817 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This file update fixes the following two security issues :

  - bsc#910252: multiple denial of service issues (resource
    consumption) (CVE-2014-8116)

  - bsc#910253: denial of service issue (resource
    consumption) (CVE-2014-8117)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00104.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00105.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=910252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=910253"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected file packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:file-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:file-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:file-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:file-magic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmagic1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmagic1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmagic1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmagic1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-magic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/29");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"file-5.15-4.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"file-debuginfo-5.15-4.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"file-debugsource-5.15-4.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"file-devel-5.15-4.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"file-magic-5.15-4.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libmagic1-5.15-4.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libmagic1-debuginfo-5.15-4.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-magic-5.15-4.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libmagic1-32bit-5.15-4.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libmagic1-debuginfo-32bit-5.15-4.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"file-5.19-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"file-debuginfo-5.19-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"file-debugsource-5.19-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"file-devel-5.19-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"file-magic-5.19-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmagic1-5.19-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libmagic1-debuginfo-5.19-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-magic-5.19-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmagic1-32bit-5.19-3.8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libmagic1-debuginfo-32bit-5.19-3.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "file / file-debuginfo / file-debugsource / file-devel / file-magic / etc");
}
