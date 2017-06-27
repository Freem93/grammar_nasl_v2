#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kdegraphics3-6211.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(38645);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0165", "CVE-2009-0166", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183");

  script_name(english:"openSUSE 10 Security Update : kdegraphics3 (kdegraphics3-6211)");
  script_summary(english:"Check for the kdegraphics3-6211 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes security problems while decoding JBIG2.
(CVE-2009-0146, CVE-2009-0147, CVE-2009-0165, CVE-2009-0166,
CVE-2009-0799, CVE-2009-0800, CVE-2009-1179, CVE-2009-1180,
CVE-2009-1181, CVE-2009-1182, CVE-2009-1183)"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdegraphics3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdegraphics3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdegraphics3-3D");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdegraphics3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdegraphics3-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdegraphics3-fax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdegraphics3-imaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdegraphics3-kamera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdegraphics3-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdegraphics3-postscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdegraphics3-scan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kdegraphics3-tex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.3", reference:"kdegraphics3-3.5.7-60.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kdegraphics3-3D-3.5.7-60.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kdegraphics3-devel-3.5.7-60.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kdegraphics3-extra-3.5.7-60.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kdegraphics3-fax-3.5.7-60.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kdegraphics3-imaging-3.5.7-60.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kdegraphics3-kamera-3.5.7-60.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kdegraphics3-pdf-3.5.7-60.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kdegraphics3-postscript-3.5.7-60.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kdegraphics3-scan-3.5.7-60.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kdegraphics3-tex-3.5.7-60.7") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdegraphics3");
}
