#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-765.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(79998);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/12/15 16:13:13 $");

  script_cve_id("CVE-2014-9130");

  script_name(english:"openSUSE Security Update : libyaml (openSUSE-SU-2014:1625-1)");
  script_summary(english:"Check for the openSUSE-2014-765 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This libyaml update fixes the following security issue :

  - bnc#907809: assert failure when processing wrapped
    strings (CVE-2014-9130)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00047.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=907809"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libyaml packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libyaml-0-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libyaml-0-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libyaml-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libyaml-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
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

if ( rpm_check(release:"SUSE12.3", reference:"libyaml-0-2-0.1.3-11.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libyaml-0-2-debuginfo-0.1.3-11.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libyaml-debugsource-0.1.3-11.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libyaml-devel-0.1.3-11.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libyaml-0-2-0.1.4-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libyaml-0-2-debuginfo-0.1.4-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libyaml-debugsource-0.1.4-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libyaml-devel-0.1.4-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libyaml-0-2-0.1.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libyaml-0-2-debuginfo-0.1.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libyaml-debugsource-0.1.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libyaml-devel-0.1.6-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libyaml-0-2 / libyaml-0-2-debuginfo / libyaml-debugsource / etc");
}
