#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-442.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(76229);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/08 14:30:48 $");

  script_cve_id("CVE-2013-4159");

  script_name(english:"openSUSE Security Update : ctdb (openSUSE-SU-2014:0842-1)");
  script_summary(english:"Check for the openSUSE-2014-442 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ctdb was updated to version 2.3 to fix several temp file
vulnerabilities (CVE-2013-4159). Various other bugs were fixed by this
upgrade, most notably bnc#867815: Avoid lockwait congestion by using
an overflow queue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-06/msg00052.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=836064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=867815"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ctdb packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-pcp-pmda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ctdb-pcp-pmda-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/26");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"ctdb-2.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ctdb-debuginfo-2.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ctdb-debugsource-2.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ctdb-devel-2.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ctdb-pcp-pmda-2.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ctdb-pcp-pmda-debuginfo-2.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ctdb-2.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ctdb-debuginfo-2.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ctdb-debugsource-2.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ctdb-devel-2.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ctdb-pcp-pmda-2.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ctdb-pcp-pmda-debuginfo-2.3-2.4.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ctdb");
}
