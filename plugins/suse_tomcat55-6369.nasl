#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update tomcat55-6369.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(42037);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/22 20:42:29 $");

  script_cve_id("CVE-2008-5515", "CVE-2009-0033", "CVE-2009-0580", "CVE-2009-0781", "CVE-2009-0783");

  script_name(english:"openSUSE 10 Security Update : tomcat55 (tomcat55-6369)");
  script_summary(english:"Check for the tomcat55-6369 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of tomcat fixes several vulnerabilities :

  - CVE-2008-5515: RequestDispatcher usage can lead to
    information leakage

  - CVE-2009-0033: denial of service via AJP connection

  - CVE-2009-0580: some authentication classes allow user
    enumeration

  - CVE-2009-0781: XSS bug in example application cal2.jsp

  - CVE-2009-0783: replacing XML parser leads to information
    leakage Additionally, non-security bugs were fixed."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat55 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 22, 79, 200);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-5.5.23-113.13") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-admin-webapps-5.5.23-113.13") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-common-lib-5.5.23-113.13") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-jasper-5.5.23-113.13") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-jasper-javadoc-5.5.23-113.13") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-jsp-2_0-api-5.5.23-113.13") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-jsp-2_0-api-javadoc-5.5.23-113.13") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-server-lib-5.5.23-113.13") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-servlet-2_4-api-5.5.23-113.13") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-servlet-2_4-api-javadoc-5.5.23-113.13") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-webapps-5.5.23-113.13") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat55 / tomcat55-admin-webapps / tomcat55-common-lib / etc");
}
