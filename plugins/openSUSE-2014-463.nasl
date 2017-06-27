#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-463.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(76721);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/07/24 10:49:39 $");

  script_cve_id("CVE-2014-4607");

  script_name(english:"openSUSE Security Update : lzo / liblzo-2-2 (openSUSE-SU-2014:0922-1)");
  script_summary(english:"Check for the openSUSE-2014-463 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"bnc#883947: CVE-2014-4607: lzo: DoS or possible RCE by allowing an
attacker to change controllflow"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-07/msg00023.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=883947"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lzo / liblzo-2-2 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblzo2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblzo2-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblzo2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:liblzo2-2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lzo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lzo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lzo-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/24");
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

if ( rpm_check(release:"SUSE12.3", reference:"liblzo2-2-2.06-9.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"liblzo2-2-debuginfo-2.06-9.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lzo-debugsource-2.06-9.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"lzo-devel-2.06-9.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"liblzo2-2-32bit-2.06-9.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"liblzo2-2-debuginfo-32bit-2.06-9.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"lzo-devel-32bit-2.06-9.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"liblzo2-2-2.06-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"liblzo2-2-debuginfo-2.06-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lzo-debugsource-2.06-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"lzo-devel-2.06-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"liblzo2-2-32bit-2.06-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"liblzo2-2-debuginfo-32bit-2.06-12.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"lzo-devel-32bit-2.06-12.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lzo / liblzo-2-2");
}
