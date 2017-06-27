#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-822.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80300);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/07/26 04:39:25 $");

  script_cve_id("CVE-2013-5704", "CVE-2014-8109");

  script_name(english:"openSUSE Security Update : apache2 (openSUSE-SU-2014:1726-1)");
  script_summary(english:"Check for the openSUSE-2014-822 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Apache2 was updated to fix bugs and security issues.

Security issues fixed: CVE-2013-5704: Added a change to fix a flaw in
the way mod_headers handled chunked requests. Adds 'MergeTrailers'
directive to restore legacy behavior [bnc#871310],

CVE-2014-8109: Fixes handling of the Require line when a
LuaAuthzProvider is used in multiple Require directives with different
arguments.

Bugfixes :

  - changed apache2.service file to fix situation where
    apache won't start at boot when using an encrypted
    certificate because user isn't prompted for password
    during boot [bnc#792309].

  - added <IfModule> around SSLSessionCache to avoid failing
    to start [bnc#842377], [bnc#849445] and [bnc#864166]."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00108.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=792309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=842377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=849445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=864166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=871310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=909715"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE12.3", reference:"apache2-2.2.29-10.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-debuginfo-2.2.29-10.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-debugsource-2.2.29-10.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-devel-2.2.29-10.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-event-2.2.29-10.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-event-debuginfo-2.2.29-10.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-example-pages-2.2.29-10.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-itk-2.2.29-10.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-itk-debuginfo-2.2.29-10.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-prefork-2.2.29-10.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-prefork-debuginfo-2.2.29-10.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-utils-2.2.29-10.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-utils-debuginfo-2.2.29-10.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-worker-2.2.29-10.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-worker-debuginfo-2.2.29-10.20.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-2.4.6-6.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-debuginfo-2.4.6-6.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-debugsource-2.4.6-6.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-devel-2.4.6-6.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-event-2.4.6-6.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-event-debuginfo-2.4.6-6.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-example-pages-2.4.6-6.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-prefork-2.4.6-6.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-prefork-debuginfo-2.4.6-6.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-utils-2.4.6-6.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-utils-debuginfo-2.4.6-6.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-worker-2.4.6-6.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-worker-debuginfo-2.4.6-6.37.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-2.4.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-debuginfo-2.4.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-debugsource-2.4.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-devel-2.4.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-event-2.4.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-event-debuginfo-2.4.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-example-pages-2.4.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-prefork-2.4.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-prefork-debuginfo-2.4.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-utils-2.4.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-utils-debuginfo-2.4.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-worker-2.4.10-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"apache2-worker-debuginfo-2.4.10-4.1") ) flag++;

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
