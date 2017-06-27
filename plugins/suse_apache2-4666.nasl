#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update apache2-4666.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(28282);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/06/13 20:06:04 $");

  script_cve_id("CVE-2006-5752", "CVE-2007-1863", "CVE-2007-3304", "CVE-2007-3847", "CVE-2007-4465");

  script_name(english:"openSUSE 10 Security Update : apache2 (apache2-4666)");
  script_summary(english:"Check for the apache2-4666 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several bugs were fixed in the Apache2 webserver :

These include the following security issues :

  - CVE-2006-5752: mod_status: Fix a possible XSS attack
    against a site with a public server-status page and
    ExtendedStatus enabled, for browsers which perform
    charset 'detection'.

  - CVE-2007-1863: mod_cache: Prevent a segmentation fault
    if attributes are listed in a Cache-Control header
    without any value.

  - CVE-2007-3304: prefork, worker, event MPMs: Ensure that
    the parent process cannot be forced to kill processes
    outside its process group.

  - CVE-2007-3847: mod_proxy: Prevent reading past the end
    of a buffer when parsing date-related headers. PR 41144.

  - CVE-2007-4465: mod_autoindex: Add in ContentType and
    Charset options to IndexOptions directive. This allows
    the admin to explicitly set the content-type and charset
    of the generated page.

and the following non-security issues :

  - get_module_list: replace loadmodule.conf atomically

  - Use File::Temp to create good tmpdir in logresolve.pl2
    (httpd-2.x.x-logresolve.patchs)"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"apache2-2.2.3-16.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"apache2-devel-2.2.3-16.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"apache2-example-pages-2.2.3-16.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"apache2-prefork-2.2.3-16.15") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"apache2-worker-2.2.3-16.15") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"apache2-2.2.3-22") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"apache2-devel-2.2.3-22") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"apache2-example-pages-2.2.3-22") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"apache2-prefork-2.2.3-22") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"apache2-worker-2.2.3-22") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"apache2-2.2.4-70.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"apache2-devel-2.2.4-70.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"apache2-example-pages-2.2.4-70.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"apache2-prefork-2.2.4-70.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"apache2-utils-2.2.4-70.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"apache2-worker-2.2.4-70.2") ) flag++;

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
