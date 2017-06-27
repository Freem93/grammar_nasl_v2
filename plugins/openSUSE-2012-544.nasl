#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-544.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74736);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-3418", "CVE-2012-3419", "CVE-2012-3420", "CVE-2012-3421");

  script_name(english:"openSUSE Security Update : pcp (openSUSE-SU-2012:1079-1)");
  script_summary(english:"Check for the openSUSE-2012-544 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to pcp-3.6.5.

  + Fixes for security advisory CVE-2012-3418; (bnc#775009).

  + Workaround for security advisory CVE-2012-3419;
    (bnc#775010).

  + Fixes for security advisory CVE-2012-3420; (bnc#775011).

  + Fixes for security advisory CVE-2012-3421; (bnc#775013)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-09/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775013"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pcp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcp-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcp3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpcp3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-import-iostat2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-import-mrtg2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-import-sar2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcp-import-sheet2pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PCP-LogImport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PCP-LogImport-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PCP-LogSummary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PCP-MMV");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PCP-MMV-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PCP-PMDA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-PCP-PMDA-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"libpcp-devel-3.6.5-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpcp-devel-debuginfo-3.6.5-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpcp3-3.6.5-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libpcp3-debuginfo-3.6.5-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"pcp-3.6.5-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"pcp-debuginfo-3.6.5-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"pcp-debugsource-3.6.5-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"pcp-import-iostat2pcp-3.6.5-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"pcp-import-mrtg2pcp-3.6.5-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"pcp-import-sar2pcp-3.6.5-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"pcp-import-sheet2pcp-3.6.5-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"perl-PCP-LogImport-3.6.5-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"perl-PCP-LogImport-debuginfo-3.6.5-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"perl-PCP-LogSummary-3.6.5-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"perl-PCP-MMV-3.6.5-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"perl-PCP-MMV-debuginfo-3.6.5-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"perl-PCP-PMDA-3.6.5-9.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"perl-PCP-PMDA-debuginfo-3.6.5-9.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pcp");
}
