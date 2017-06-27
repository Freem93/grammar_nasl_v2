#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-81.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75187);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/07/10 14:11:56 $");

  script_cve_id("CVE-2012-2687");
  script_osvdb_id(84818);

  script_name(english:"openSUSE Security Update : apache2 (openSUSE-SU-2013:0245-1)");
  script_summary(english:"Check for the openSUSE-2013-81 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"- httpd-2.2.x-bnc798733-SNI_ignorecase.diff: ignore case when
checking against SNI server names. [bnc#798733]

- httpd-2.2.x-bnc777260-CVE-2012-2687-mod_negotiation_filename_xss.diff
Escape filename for the case that uploads are allowed with untrusted
user's control over filenames and mod_negotiation enabled on the
same directory. CVE-2012-2687 [bnc#777260]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-02/msg00011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=798733"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/29");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"apache2-2.2.22-4.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"apache2-debuginfo-2.2.22-4.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"apache2-debugsource-2.2.22-4.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"apache2-devel-2.2.22-4.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"apache2-event-2.2.22-4.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"apache2-event-debuginfo-2.2.22-4.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"apache2-example-pages-2.2.22-4.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"apache2-itk-2.2.22-4.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"apache2-itk-debuginfo-2.2.22-4.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"apache2-prefork-2.2.22-4.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"apache2-prefork-debuginfo-2.2.22-4.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"apache2-utils-2.2.22-4.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"apache2-utils-debuginfo-2.2.22-4.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"apache2-worker-2.2.22-4.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"apache2-worker-debuginfo-2.2.22-4.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2 / apache2-debuginfo / apache2-debugsource / apache2-devel / etc");
}
