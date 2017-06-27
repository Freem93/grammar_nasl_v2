#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-638.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75110);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/07/10 14:11:56 $");

  script_cve_id("CVE-2013-1862", "CVE-2013-1896");
  script_osvdb_id(93366, 95498);

  script_name(english:"openSUSE Security Update : apache2 (openSUSE-SU-2013:1340-1)");
  script_summary(english:"Check for the openSUSE-2013-638 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"- httpd-2.2.x-bnc829056-CVE-2013-1896-pr1482522-mod_dav.diff
CVE-2013-1896: Sending a MERGE request against a URI handled by
mod_dav_svn with the source href
  (sent as part of the request
body as XML) pointing to a URI that is not configured for DAV will
trigger a segfault. [bnc#829056]

- httpd-2.2.x-bnc829057-CVE-2013-1862-mod_rewrite_terminal_escape_sequences.diff
CVE-2013-1862: client data written to the RewriteLog must have
terminal escape sequences escaped. [bnc#829057]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-08/msg00029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829057"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"apache2-2.2.22-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-debuginfo-2.2.22-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-debugsource-2.2.22-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-devel-2.2.22-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-event-2.2.22-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-event-debuginfo-2.2.22-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-example-pages-2.2.22-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-itk-2.2.22-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-itk-debuginfo-2.2.22-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-prefork-2.2.22-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-prefork-debuginfo-2.2.22-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-utils-2.2.22-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-utils-debuginfo-2.2.22-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-worker-2.2.22-10.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"apache2-worker-debuginfo-2.2.22-10.8.1") ) flag++;

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
