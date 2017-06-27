#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update texlive-bin-5221.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(32184);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/22 20:42:28 $");

  script_cve_id("CVE-2007-5935", "CVE-2007-5936", "CVE-2007-5937");

  script_name(english:"openSUSE 10 Security Update : texlive-bin (texlive-bin-5221)");
  script_summary(english:"Check for the texlive-bin-5221 patch");

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
    value:"Update the affected texlive-bin packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-bin-cjk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-bin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-bin-dvilj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-bin-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-bin-metapost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-bin-omega");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:texlive-bin-xetex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/09");
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
if (release !~ "^(SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.3", reference:"texlive-bin-2007-68.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"texlive-bin-cjk-2007-68.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"texlive-bin-devel-2007-68.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"texlive-bin-dvilj-2007-68.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"texlive-bin-latex-2007-68.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"texlive-bin-metapost-2007-68.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"texlive-bin-omega-2007-68.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"texlive-bin-xetex-2007-68.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "texlive-bin / texlive-bin-cjk / texlive-bin-devel / etc");
}
