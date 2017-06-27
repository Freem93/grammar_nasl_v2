#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update apache2-mod_jk-4997.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(31338);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/22 20:32:45 $");

  script_cve_id("CVE-2007-1860", "CVE-2007-3382", "CVE-2007-3385", "CVE-2007-3386", "CVE-2007-5342", "CVE-2007-5641");

  script_name(english:"openSUSE 10 Security Update : apache2-mod_jk (apache2-mod_jk-4997)");
  script_summary(english:"Check for the apache2-mod_jk-4997 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fixed various issues in tomcat :

  - CVE-2007-3382: Handling of cookies containing a '
    character

  - CVE-2007-3385: Handling of \' in cookies

  - CVE-2007-5641: tomcat path traversal / information leak

  - CVE-2007-1860: directory traversal

  - CVE-2007-3386: tomcat XSS 

  - CVE-2007-5342: insufficient access restrictions

Additionally the dbcp namespace in commons-dbcp.jar was fixed."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2-mod_jk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 22, 79, 94, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-mod_jk");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/04");
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

if ( rpm_check(release:"SUSE10.3", reference:"apache2-mod_jk-1.2.21-59.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-5.5.23-113.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-admin-webapps-5.5.23-113.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-common-lib-5.5.23-113.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-jasper-5.5.23-113.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-jasper-javadoc-5.5.23-113.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-jsp-2_0-api-5.5.23-113.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-jsp-2_0-api-javadoc-5.5.23-113.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-server-lib-5.5.23-113.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-servlet-2_4-api-5.5.23-113.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-servlet-2_4-api-javadoc-5.5.23-113.3") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"tomcat55-webapps-5.5.23-113.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2-mod_jk / tomcat55 / tomcat55-admin-webapps / etc");
}
