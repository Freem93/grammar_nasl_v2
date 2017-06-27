#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-816.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80276);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/12/29 13:38:34 $");

  script_cve_id("CVE-2013-6435", "CVE-2014-8118");

  script_name(english:"openSUSE Security Update : python3-rpm / rpm / rpm-python (openSUSE-SU-2014:1716-1)");
  script_summary(english:"Check for the openSUSE-2014-816 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This rpm update fixes the following security and non security issues :

  - honor --noglob in install mode [bnc#892431]

  - check for bad invalid name sizes [bnc#908128]
    [CVE-2014-8118]

  - create files with mode 0 [bnc#906803] [CVE-2013-6435]

This update also includes version updates of rpm-python and
python3-rpm."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00100.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=892431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=906803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908128"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python3-rpm / rpm / rpm-python packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rpm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-build-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rpm-python-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/29");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"python3-rpm-4.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-rpm-debuginfo-4.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python3-rpm-debugsource-4.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"rpm-4.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"rpm-build-4.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"rpm-build-debuginfo-4.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"rpm-debuginfo-4.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"rpm-debugsource-4.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"rpm-devel-4.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"rpm-python-4.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"rpm-python-debuginfo-4.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"rpm-python-debugsource-4.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"rpm-32bit-4.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"rpm-debuginfo-32bit-4.10.2-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-rpm-4.11.1-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-rpm-debuginfo-4.11.1-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python3-rpm-debugsource-4.11.1-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rpm-4.11.1-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rpm-build-4.11.1-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rpm-build-debuginfo-4.11.1-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rpm-debuginfo-4.11.1-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rpm-debugsource-4.11.1-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rpm-devel-4.11.1-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rpm-python-4.11.1-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rpm-python-debuginfo-4.11.1-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"rpm-python-debugsource-4.11.1-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"rpm-32bit-4.11.1-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"rpm-debuginfo-32bit-4.11.1-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-rpm-4.11.3-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-rpm-debuginfo-4.11.3-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python3-rpm-debugsource-4.11.3-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"rpm-4.11.3-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"rpm-build-4.11.3-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"rpm-build-debuginfo-4.11.3-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"rpm-debuginfo-4.11.3-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"rpm-debugsource-4.11.3-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"rpm-devel-4.11.3-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"rpm-python-4.11.3-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"rpm-python-debuginfo-4.11.3-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"rpm-python-debugsource-4.11.3-4.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"rpm-32bit-4.11.3-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"rpm-debuginfo-32bit-4.11.3-4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python3-rpm / python3-rpm-debuginfo / python3-rpm-debugsource / etc");
}
