#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-132.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74555);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/16 16:21:30 $");

  script_cve_id("CVE-2007-6750", "CVE-2011-3607", "CVE-2012-0031", "CVE-2012-0053");

  script_name(english:"openSUSE Security Update : apache2 (openSUSE-2012-132)");
  script_summary(english:"Check for the openSUSE-2012-132 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"- httpd-2.2.x-bnc743743-CVE-2012-0053-server_protocol_c-cookie_exposure.diff
addresses CVE-2012-0053: error responses can expose cookies when
no custom 400 error code ErrorDocument is configured. [bnc#743743]

- httpd-2.2.x-bnc741243-CVE-2012-0031-scoreboard_handling.diff:
scoreboard corruption
  (shared mem segment) by child causes
crash of privileged parent (invalid free()) during shutdown.
This is rated low impact. Notice:
https://svn.apache.org/viewvc?view=revision&revision=1230065
makes a change to the struct global_score, which causes binary
incompatibility. The change in above patch only goes as far as
the binary compatibility allows; the vulnerability is completely
fixed, though. CVE-2012-0031 [bnc#741243]

  - /etc/init.d/apache2: new argument 'check-reload'. Exits
    1 if httpd2 runs on deleted binaries such as after
    package update, else 0. This is used by equally modified
    /etc/logrotate.d/apache2, which uses
    '/etc/init.d/apache2 check-reload' in its prerotate
    script. These changes prevent httpd2 from being
    (gracefully) reloaded by logrotate, executed by cron, if
    new binaries have been installed. Instead, a warning is
    printed on stdout and is being logged to the syslogs. If
    this happens, apache's logs are NOT rotated, and the
    running processes are left untouched. This limits the
    maximum damage of log rotation to unrotated logs.
    '/etc/init.d/apache2 restart' (or 'rcapache2 restart')
    must be executed manually in such a case. [bnc#728876]

- httpd-2.2.x-bnc729181-CVE-2011-3607-int_overflow.diff: Fix for
integer overflow in server/util.c also known as CVE-2011-3607.
[bnc#729181]

  - enable build and configuration of mod_reqtimeout.c
    module by default in /etc/sysconfig/apache2
    (APACHE_MODULES=...). This does not change already
    existing sysconfig files, the module is only activated
    via sysconfig if this package is installed without
    pre-existing sysconfig file. See new file
    /etc/apache2/mod_reqtimeout.conf for configurables.
    Helps against Slowloris.pl DoS vulnerability that
    consists of eating up request slots by very slowly
    submitting the request. Note that mod_reqtimeout limits
    requests based on a lower boundary of request speed, not
    an upper boundary! CVE-2007-6750 [bnc#738855]."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=728876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=729181"
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
    attribute:"see_also",
    value:"https://svn.apache.org/viewvc?view=revision&revision=1230065"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-event-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-itk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-itk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"apache2-2.2.21-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-debuginfo-2.2.21-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-debugsource-2.2.21-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-devel-2.2.21-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-event-2.2.21-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-event-debuginfo-2.2.21-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-example-pages-2.2.21-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-itk-2.2.21-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-itk-debuginfo-2.2.21-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-prefork-2.2.21-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-prefork-debuginfo-2.2.21-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-utils-2.2.21-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-utils-debuginfo-2.2.21-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-worker-2.2.21-3.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"apache2-worker-debuginfo-2.2.21-3.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2 / apache2-debuginfo / apache2-debugsource / apache2-devel / etc");
}
