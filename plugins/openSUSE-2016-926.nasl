#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-926.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(92715);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/10/13 14:37:13 $");

  script_cve_id("CVE-2016-6265");

  script_name(english:"openSUSE Security Update : mupdf (openSUSE-2016-926)");
  script_summary(english:"Check for the openSUSE-2016-926 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mupdf fixes the following issues :

Security issues fixed :

  - CVE-2016-6265: Fixed a use-after-free issue
    (boo#990195)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990195"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mupdf packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mupdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mupdf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mupdf-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mupdf-devel-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"mupdf-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mupdf-debuginfo-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mupdf-debugsource-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mupdf-devel-static-1.5-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mupdf-1.7a-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mupdf-debuginfo-1.7a-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mupdf-debugsource-1.7a-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"mupdf-devel-static-1.7a-7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mupdf / mupdf-debuginfo / mupdf-debugsource / mupdf-devel-static");
}
