#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-658.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86393);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/01/27 23:31:26 $");

  script_cve_id("CVE-2015-0254");

  script_name(english:"openSUSE Security Update : jakarta-taglibs-standard (openSUSE-2015-658)");
  script_summary(english:"Check for the openSUSE-2015-658 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"jakarta-taglibs-standard was updated to fix one security issue.

This security issue was fixed :

  - CVE-2015-0254: Apache Standard Taglibs before 1.2.3
    allowed remote attackers to execute arbitrary code or
    conduct external XML entity (XXE) attacks via a crafted
    XSLT extension (bsc#920813)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=920813"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jakarta-taglibs-standard packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jakarta-taglibs-standard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jakarta-taglibs-standard-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xalan-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xalan-j2-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xalan-j2-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xalan-j2-xsltc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"jakarta-taglibs-standard-1.1.1-252.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"jakarta-taglibs-standard-javadoc-1.1.1-252.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xalan-j2-2.7.2-262.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xalan-j2-demo-2.7.2-262.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xalan-j2-manual-2.7.2-262.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xalan-j2-xsltc-2.7.2-262.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"jakarta-taglibs-standard-1.1.1-255.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"jakarta-taglibs-standard-javadoc-1.1.1-255.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jakarta-taglibs-standard / jakarta-taglibs-standard-javadoc / etc");
}
