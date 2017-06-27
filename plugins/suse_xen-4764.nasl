#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update xen-4764.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(29891);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/06/13 20:36:50 $");

  script_cve_id("CVE-2007-5906", "CVE-2007-5907");

  script_name(english:"openSUSE 10 Security Update : xen (xen-4764)");
  script_summary(english:"Check for the xen-4764 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes various Xen issues.

Two security problems were fixed: CVE-2007-5906: Xen allowed virtual
guest system users to cause a denial of service (hypervisor crash) by
using a debug register (DR7) to set certain breakpoints.

CVE-2007-5907: Xen 3.1.1 does not prevent modification of the CR4 TSC
from applications, which allows pv guests to cause a denial of service
(crash).

Also the following bugs were fixed: 279062: Timer ISR/1: Time went
backwards 340379: Xen-3.04_13138-0.52 not working with FV File-Backed
VMs"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-ps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-ioemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"xen-3.0.4_13138-0.60") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xen-devel-3.0.4_13138-0.60") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xen-doc-html-3.0.4_13138-0.60") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xen-doc-pdf-3.0.4_13138-0.60") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xen-doc-ps-3.0.4_13138-0.60") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xen-libs-3.0.4_13138-0.60") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xen-tools-3.0.4_13138-0.60") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"xen-tools-ioemu-3.0.4_13138-0.60") ) flag++;
if ( rpm_check(release:"SUSE10.1", cpu:"x86_64", reference:"xen-libs-32bit-3.0.4_13138-0.60") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-devel / xen-doc-html / xen-doc-pdf / xen-doc-ps / etc");
}
