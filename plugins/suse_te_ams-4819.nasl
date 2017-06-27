#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update te_ams-4819.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(29890);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/22 20:42:28 $");

  script_cve_id("CVE-2007-5935", "CVE-2007-5936", "CVE-2007-5937");

  script_name(english:"openSUSE 10 Security Update : te_ams (te_ams-4819)");
  script_summary(english:"Check for the te_ams-4819 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Buffer overflows in dvips and dviljk could be triggered by specially
crafted dvi files (CVE-2007-5935, CVE-2007-5937). dvips additionally
created temporary files in an insecure manner (CVE-2007-5936)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected te_ams packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:te_ams");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:te_cont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:te_dvilj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:te_eplai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:te_kpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:te_latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:te_mpost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:te_nfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:te_omega");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:te_ptex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:te_web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tetex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/08");
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
if (release !~ "^(SUSE10\.1|SUSE10\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1 / 10.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"te_ams-3.0-37.7") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"te_cont-3.0-37.7") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"te_dvilj-3.0-37.7") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"te_eplai-3.0-37.7") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"te_kpath-3.0-37.7") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"te_latex-3.0-37.7") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"te_mpost-3.0-37.7") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"te_nfs-3.0-37.7") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"te_omega-3.0-37.7") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"te_ptex-3.0-37.7") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"te_web-3.0-37.7") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"tetex-3.0-37.7") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"te_ams-3.0-60") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"te_cont-3.0-60") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"te_dvilj-3.0-60") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"te_eplai-3.0-60") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"te_kpath-3.0-60") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"te_latex-3.0-60") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"te_mpost-3.0-60") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"te_nfs-3.0-60") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"te_omega-3.0-60") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"te_ptex-3.0-60") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"te_web-3.0-60") ) flag++;
if ( rpm_check(release:"SUSE10.2", reference:"tetex-3.0-60") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "te_ams / te_cont / te_dvilj / te_eplai / te_kpath / te_latex / etc");
}
