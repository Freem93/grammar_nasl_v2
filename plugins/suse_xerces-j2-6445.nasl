#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update xerces-j2-6445.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(42041);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/06/13 20:36:50 $");

  script_cve_id("CVE-2009-2625");

  script_name(english:"openSUSE 10 Security Update : xerces-j2 (xerces-j2-6445)");
  script_summary(english:"Check for the xerces-j2-6445 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The xerces-j2 package was vulnerable to various bugs while parsing
XML.CVE-2009-2625 has been assigned to this issue."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xerces-j2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xerces-j2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xerces-j2-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xerces-j2-javadoc-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xerces-j2-javadoc-dom3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xerces-j2-javadoc-impl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xerces-j2-javadoc-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xerces-j2-javadoc-xni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xerces-j2-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xerces-j2-xml-apis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xerces-j2-xml-resolver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE10.3", reference:"xerces-j2-2.8.1-85.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xerces-j2-demo-2.8.1-85.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xerces-j2-javadoc-apis-2.8.1-85.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xerces-j2-javadoc-dom3-2.8.1-85.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xerces-j2-javadoc-impl-2.8.1-85.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xerces-j2-javadoc-other-2.8.1-85.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xerces-j2-javadoc-xni-2.8.1-85.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xerces-j2-scripts-2.8.1-85.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xerces-j2-xml-apis-2.8.1-85.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"xerces-j2-xml-resolver-2.8.1-85.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xerces-j2");
}
