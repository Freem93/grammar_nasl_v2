#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update cups-5652.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(34358);
  script_version ("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/22 20:32:45 $");

  script_cve_id("CVE-2008-3639", "CVE-2008-3640", "CVE-2008-3641");

  script_name(english:"openSUSE 10 Security Update : cups (cups-5652)");
  script_summary(english:"Check for the cups-5652 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Specially crafted print jobs could trigger buffer overflows in the
'imagetops', 'texttops' and 'hpgltops' filters. Attackers could
potentially exploit that to execute arbitrary code on the cups server
(CVE-2008-3639, CVE-2008-3640, CVE-2008-3641)."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cups-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.2", reference:"cups-1.2.7-12.19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"cups-client-1.2.7-12.19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"cups-devel-1.2.7-12.19") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"cups-libs-1.2.7-12.19") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"cups-libs-32bit-1.2.7-12.19") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"cups-1.2.12-22.17") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"cups-client-1.2.12-22.17") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"cups-devel-1.2.12-22.17") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"cups-libs-1.2.12-22.17") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"cups-libs-32bit-1.2.12-22.17") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cups / cups-client / cups-devel / cups-libs / cups-libs-32bit");
}
