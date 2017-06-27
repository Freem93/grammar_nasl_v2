#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update tomcat55-5385.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(33435);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/06/13 20:36:50 $");

  script_cve_id("CVE-2008-1947");

  script_name(english:"openSUSE 10 Security Update : tomcat55 (tomcat55-5385)");
  script_summary(english:"Check for the tomcat55-5385 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of tomcat fixes a cross-site-scripting vulnerabilitiy in
the host-manager. (CVE-2008-1947)"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat55 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat55-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat55-common-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat55-jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat55-jasper-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat55-jsp-2_0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat55-jsp-2_0-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat55-server-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat55-servlet-2_4-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat55-servlet-2_4-api-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat55-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-5.5.23-113.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-admin-webapps-5.5.23-113.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-common-lib-5.5.23-113.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-jasper-5.5.23-113.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-jasper-javadoc-5.5.23-113.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-jsp-2_0-api-5.5.23-113.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-jsp-2_0-api-javadoc-5.5.23-113.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-server-lib-5.5.23-113.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-servlet-2_4-api-5.5.23-113.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-servlet-2_4-api-javadoc-5.5.23-113.7") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-webapps-5.5.23-113.7") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat");
}
