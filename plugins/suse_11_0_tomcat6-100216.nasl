#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update tomcat6-2000.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(45456);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/21 20:09:50 $");

  script_cve_id("CVE-2008-5515", "CVE-2009-2693", "CVE-2009-2901", "CVE-2009-2902");

  script_name(english:"openSUSE Security Update : tomcat6 (tomcat6-2000)");
  script_summary(english:"Check for the tomcat6-2000 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of tomcat5/6 fixes :

  - CVE-2009-2693: CVSS v2 Base Score: 5.8 CVE-2009-2902:
    CVSS v2 Base Score: 4.3 Directory traversal
    vulnerability allowed remote attackers to create or
    overwrite arbitrary files/dirs with a specially crafted
    WAR file.

  - CVE-2009-2901: CVSS v2 Base Score: 4.3 When autoDeploy
    is enabled the autodeployment process deployed appBase
    files that remain from a failed undeploy, which might
    allow remote attackers to bypass intended authentication
    requirements via HTTP requests.

  - CVE-2008-5515: CVSS v2 Base Score: 5.0 When using the
    RequestDispatcher method, i was possible for remote
    attackers to bypass intended access restrictions and
    conduct directory traversal attacks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=575083"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat6 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cwe_id(22, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-jsp-2_1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-servlet-2_5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"tomcat6-6.0.16-6.7") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"tomcat6-admin-webapps-6.0.16-6.7") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"tomcat6-docs-webapp-6.0.16-6.7") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"tomcat6-javadoc-6.0.16-6.7") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"tomcat6-jsp-2_1-api-6.0.16-6.7") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"tomcat6-lib-6.0.16-6.7") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"tomcat6-servlet-2_5-api-6.0.16-6.7") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"tomcat6-webapps-6.0.16-6.7") ) flag++;

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
