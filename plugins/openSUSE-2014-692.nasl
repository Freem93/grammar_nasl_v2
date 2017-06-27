#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-692.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(79368);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/21 11:41:43 $");

  script_cve_id("CVE-2014-3421", "CVE-2014-3422", "CVE-2014-3423", "CVE-2014-3424");

  script_name(english:"openSUSE Security Update : emacs (openSUSE-SU-2014:1460-1)");
  script_summary(english:"Check for the openSUSE-2014-692 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"emacs was updated to fix four security issues.

These security issues were fixed :

  - Avoid unsecure usage of temporary files (CVE-2014-3421).

  - Avoid unsecure usage of temporary files (CVE-2014-3422).

  - Avoid unsecure usage of temporary files (CVE-2014-3423).

  - Avoid unsecure usage of temporary files (CVE-2014-3424)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-11/msg00080.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=876847"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected emacs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-nox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:emacs-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:etags");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:etags-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/21");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"emacs-24.3-6.14.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"emacs-debuginfo-24.3-6.14.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"emacs-debugsource-24.3-6.14.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"emacs-el-24.3-6.14.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"emacs-info-24.3-6.14.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"emacs-nox-24.3-6.14.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"emacs-nox-debuginfo-24.3-6.14.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"emacs-x11-24.3-6.14.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"emacs-x11-debuginfo-24.3-6.14.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"etags-24.3-6.14.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"etags-debuginfo-24.3-6.14.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs / emacs-debuginfo / emacs-debugsource / emacs-el / emacs-info / etc");
}
