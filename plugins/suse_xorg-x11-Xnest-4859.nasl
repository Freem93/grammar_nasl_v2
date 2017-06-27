#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update xorg-x11-Xnest-4859.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(30017);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/22 20:42:29 $");

  script_cve_id("CVE-2007-5760", "CVE-2007-5958", "CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429");

  script_name(english:"openSUSE 10 Security Update : xorg-x11-Xnest (xorg-x11-Xnest-4859)");
  script_summary(english:"Check for the xorg-x11-Xnest-4859 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes various Xserver security issues. File existence
disclosure vulnerability (CVE-2007-5958).

XInput Extension Memory Corruption Vulnerability [IDEF2888
CVE-2007-6427].

TOG-CUP Extension Memory Corruption Vulnerability [IDEF2901
CVE-2007-6428].

EVI Extension Integer Overflow Vulnerability [IDEF2902 CVE-2007-6429].

MIT-SHM Extension Integer Overflow Vulnerability [IDEF2904
CVE-2007-6429]. 

XFree86-MISC Extension Invalid Array Index Vulnerability [IDEF2903
CVE-2007-5760]. 

PCF font parser vulnerability."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-Xnest packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189, 200, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/18");
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

if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-Xnest-6.9.0-50.54.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-Xvfb-6.9.0-50.54.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-devel-6.9.0-50.54.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-libs-6.9.0-50.54.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xorg-x11-server-6.9.0-50.54.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"xorg-x11-devel-32bit-6.9.0-50.54.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"xorg-x11-libs-32bit-6.9.0-50.54.5") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"xorg-x11-devel-7.2-25") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"xorg-x11-libs-7.2-25") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"xorg-x11-server-7.2-30.11") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"xorg-x11-server-sdk-7.2-30.11") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"xorg-x11-devel-32bit-7.2-25") ) flag++;
if ( rpm_check(release:"SUSE10.2", cpu:"x86_64", reference:"xorg-x11-libs-32bit-7.2-25") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xorg-x11-devel-7.2-103.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xorg-x11-libs-7.2-103.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xorg-x11-server-7.2-143.9") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xorg-x11-server-extra-7.2-143.9") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xorg-x11-server-sdk-7.2-143.9") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"xorg-x11-devel-32bit-7.2-103.4") ) flag++;
if ( rpm_check(release:"SUSE10.3", cpu:"x86_64", reference:"xorg-x11-libs-32bit-7.2-103.4") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-Xnest / xorg-x11-Xvfb / xorg-x11-devel / etc");
}
