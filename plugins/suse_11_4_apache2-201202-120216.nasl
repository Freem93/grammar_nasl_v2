#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update apache2-201202-5821.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75789);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/16 16:21:30 $");

  script_cve_id("CVE-2007-6750", "CVE-2012-0031", "CVE-2012-0053");

  script_name(english:"openSUSE Security Update : apache2-201202 (openSUSE-SU-2012:0314-1)");
  script_summary(english:"Check for the apache2-201202-5821 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of apache2 fixes regressions and several security 
problems :

bnc#728876, fix graceful reload

bnc#741243, CVE-2012-0031: Fixed a scoreboard corruption (shared mem
segment) by child causes crash of privileged parent (invalid free())
during shutdown.

bnc#743743, CVE-2012-0053: Fixed an issue in error responses that
could expose 'httpOnly' cookies when no custom ErrorDocument is
specified for status code 400'.

bnc#738855, CVE-2007-6750: The 'mod_reqtimeout' module was backported
from Apache 2.2.21 to help mitigate the 'Slowloris' Denial of Service
attack.

You need to enable the 'mod_reqtimeout' module in your existing apache
configuration to make it effective, e.g. in the APACHE_MODULES line in
/etc/sysconfig/apache2."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-02/msg00065.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=728876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=738855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=741243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=743743"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2-201202 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-example-certificates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-itk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-itk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"apache2-2.2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-debuginfo-2.2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-debugsource-2.2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-devel-2.2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-example-certificates-2.2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-example-pages-2.2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-itk-2.2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-itk-debuginfo-2.2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-prefork-2.2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-prefork-debuginfo-2.2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-utils-2.2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-utils-debuginfo-2.2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-worker-2.2.17-4.13.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"apache2-worker-debuginfo-2.2.17-4.13.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2");
}
