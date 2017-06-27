#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-401.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75379);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2014-3215");
  script_bugtraq_id(67341);

  script_name(english:"openSUSE Security Update : libcap-ng (openSUSE-SU-2014:0736-1)");
  script_summary(english:"Check for the openSUSE-2014-401 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Besides other enhancements, this version update contains :

  - fix for CVE-2014-3215 (bnc#876832)

  - use PR_SET_NO_NEW_PRIVS to prevent gain of new
    privileges

  - added libcap-ng-CVE-2014-3215.patch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-05/msg00084.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=876832"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libcap-ng packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcap-ng-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcap-ng-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcap-ng-python-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcap-ng-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcap-ng-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcap-ng0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcap-ng0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcap-ng0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcap-ng0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-capng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-capng-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/21");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"libcap-ng-debugsource-0.6.6-11.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libcap-ng-devel-0.6.6-11.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libcap-ng-python-debugsource-0.6.6-11.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libcap-ng-utils-0.6.6-11.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libcap-ng-utils-debuginfo-0.6.6-11.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libcap-ng0-0.6.6-11.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libcap-ng0-debuginfo-0.6.6-11.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-capng-0.6.6-11.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-capng-debuginfo-0.6.6-11.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libcap-ng0-32bit-0.6.6-11.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libcap-ng0-debuginfo-32bit-0.6.6-11.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libcap-ng-debugsource-0.7.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libcap-ng-devel-0.7.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libcap-ng-python-debugsource-0.7.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libcap-ng-utils-0.7.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libcap-ng-utils-debuginfo-0.7.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libcap-ng0-0.7.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libcap-ng0-debuginfo-0.7.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-capng-0.7.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-capng-debuginfo-0.7.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libcap-ng0-32bit-0.7.3-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libcap-ng0-debuginfo-32bit-0.7.3-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcap-ng-python-debugsource / python-capng / etc");
}
