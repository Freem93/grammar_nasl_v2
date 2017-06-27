#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-766.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86924);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/12/09 15:05:38 $");

  script_cve_id("CVE-2015-5309");

  script_name(english:"openSUSE Security Update : putty (openSUSE-2015-766)");
  script_summary(english:"Check for the openSUSE-2015-766 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"PuTTY was updated to 0.66 to fix security issues and bugs.

The following vulnerabilities were fixed :

  - CVE-2015-5309: Malicious ECH control sequences could
    have caused an integer overflow, buffer underrun in
    terminal emulator bnc#954191

Also contains all bug fixes up to the 0.66 release."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954191"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected putty packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:putty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:putty-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:putty-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/19");
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

if ( rpm_check(release:"SUSE13.1", reference:"putty-0.66-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"putty-debuginfo-0.66-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"putty-debugsource-0.66-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"putty-0.66-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"putty-debuginfo-0.66-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"putty-debugsource-0.66-4.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"putty-0.66-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"putty-debuginfo-0.66-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"putty-debugsource-0.66-6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "putty / putty-debuginfo / putty-debugsource");
}
