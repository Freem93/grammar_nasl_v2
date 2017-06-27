#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update ganglia-monitor-core-894.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(39966);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/13 19:38:12 $");

  script_cve_id("CVE-2009-0241");

  script_name(english:"openSUSE Security Update : ganglia-monitor-core (ganglia-monitor-core-894)");
  script_summary(english:"Check for the ganglia-monitor-core-894 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A stack-based buffer overflow in ganglia's buffer process_path
function has been fixed. CVE-2009-0241 has been assigned to this
issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=484338"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ganglia-monitor-core packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ganglia-monitor-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ganglia-monitor-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ganglia-monitor-core-gmetad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ganglia-monitor-core-gmond");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ganglia-webfrontend");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"ganglia-monitor-core-2.5.7-162.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"ganglia-monitor-core-devel-2.5.7-162.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"ganglia-monitor-core-gmetad-2.5.7-162.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"ganglia-monitor-core-gmond-2.5.7-162.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"ganglia-webfrontend-2.5.7-162.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ganglia-monitor-core / ganglia-monitor-core-devel / etc");
}
