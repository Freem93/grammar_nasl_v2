#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update tomcat6-3945.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75761);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:55:23 $");

  script_cve_id("CVE-2010-3718", "CVE-2011-0013", "CVE-2011-0534");

  script_name(english:"openSUSE Security Update : tomcat6 (openSUSE-SU-2011:0146-1)");
  script_summary(english:"Check for the tomcat6-3945 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This tomcat6 update fixes :

  - CVE-2010-3718: CVSS v2 Base Score: 4.0
    (AV:N/AC:H/Au:N/C:P/I:P/A:N): Design Error
    (CWE-DesignError)

  - CVE-2011-0013: CVSS v2 Base Score: 4.3
    (AV:N/AC:M/Au:N/C:N/I:P/A:N): XSS (CWE-79)

  - CVE-2011-0534: CVSS v2 Base Score: 5.0
    (AV:N/AC:L/Au:N/C:N/I:N/A:P): Resource Management Errors
    (CWE-399)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-03/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=669897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=669929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=669930"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat6 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-el-1_0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-jsp-2_1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-servlet-2_5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"tomcat6-6.0.24-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"tomcat6-admin-webapps-6.0.24-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"tomcat6-docs-webapp-6.0.24-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"tomcat6-el-1_0-api-6.0.24-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"tomcat6-javadoc-6.0.24-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"tomcat6-jsp-2_1-api-6.0.24-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"tomcat6-lib-6.0.24-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"tomcat6-servlet-2_5-api-6.0.24-5.10.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"tomcat6-webapps-6.0.24-5.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat6");
}
