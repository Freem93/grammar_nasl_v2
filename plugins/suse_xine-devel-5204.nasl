#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update xine-devel-5204.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(32392);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/22 20:42:29 $");

  script_cve_id("CVE-2008-1686", "CVE-2008-1878");

  script_name(english:"openSUSE 10 Security Update : xine-devel (xine-devel-5204)");
  script_summary(english:"Check for the xine-devel-5204 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Specially crafted NSF files could potentially be exploited to execute
arbitrary code (CVE-2008-1878).

Specially crafted files or streams could potentially be abused to
trick applications that support speex into executing arbitrary code
(CVE-2008-1686)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xine-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xine-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xine-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xine-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xine-lib-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xine-ui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xine-ui-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/20");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2|SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2 / 10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"xine-devel-1.1.1-24.39") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xine-extra-1.1.1-24.39") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xine-lib-1.1.1-24.39") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xine-ui-0.99.4-32.35") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"xine-lib-32bit-1.1.1-24.39") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"xine-devel-1.1.2-40.13") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"xine-extra-1.1.2-40.13") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"xine-lib-1.1.2-40.13") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"xine-ui-0.99.4-84.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"xine-lib-32bit-1.1.2-40.13") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"xine-ui-32bit-0.99.4-84.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xine-devel-1.1.8-14.9") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xine-extra-1.1.8-14.9") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xine-lib-1.1.8-14.9") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xine-ui-0.99.5-62.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"xine-lib-32bit-1.1.8-14.9") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xine-devel / xine-extra / xine-lib / xine-lib-32bit / xine-ui / etc");
}
