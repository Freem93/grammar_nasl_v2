#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-503.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(77292);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/07/26 04:39:25 $");

  script_cve_id("CVE-2013-4352", "CVE-2013-6438", "CVE-2014-0098", "CVE-2014-0117", "CVE-2014-0226", "CVE-2014-0231");

  script_name(english:"openSUSE Security Update : apache2 (openSUSE-SU-2014:1044-1)");
  script_summary(english:"Check for the openSUSE-2014-503 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This apache2 update fixes the following security issues :

  - fix for crash in mod_proxy processing specially crafted
    requests with reverse proxy configurations that results
    in a crash and a DoS condition for the server.
    CVE-2014-0117

  - new config option CGIDScriptTimeout set to 60s in new
    file conf.d/cgid-timeout.conf, preventing worker
    processes hanging forever if a cgi launched from them
    has stopped reading input from the server (DoS).
    CVE-2014-0231

  - Fix for a NULL pointer dereference in mod_cache that
    causes a crash in caching forwarding configurations,
    resulting in a DoS condition. CVE-2013-4352

  - fix for crash in parsing cookie content, resulting in a
    DoS against the server CVE-2014-0098

  - fix for mod_status race condition in scoreboard handling
    and consecutive heap overflow and information disclosure
    if access to mod_status is granted to a potential
    attacker. CVE-2014-0226

  - fix for improper handling of whitespace characters from
    CDATA sections to mod_dav, leading to a crash and a DoS
    condition of the apache server process CVE-2013-6438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-08/msg00031.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=869105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=869106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=887765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=887767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=887768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=887771"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-event-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/21");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"apache2-2.4.6-6.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-debuginfo-2.4.6-6.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-debugsource-2.4.6-6.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-devel-2.4.6-6.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-event-2.4.6-6.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-event-debuginfo-2.4.6-6.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-example-pages-2.4.6-6.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-prefork-2.4.6-6.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-prefork-debuginfo-2.4.6-6.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-utils-2.4.6-6.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-utils-debuginfo-2.4.6-6.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-worker-2.4.6-6.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"apache2-worker-debuginfo-2.4.6-6.27.1") ) flag++;

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
