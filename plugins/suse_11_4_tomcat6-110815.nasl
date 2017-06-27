#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update tomcat6-5002.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(76034);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:19:38 $");

  script_cve_id("CVE-2011-2204", "CVE-2011-2526");

  script_name(english:"openSUSE Security Update : tomcat6 (openSUSE-SU-2011:0988-1)");
  script_summary(english:"Check for the tomcat6-5002 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following security issues were fixed in tomcat :

  - Fixed a tomcat user password information leak
    (CVE-2011-2204)

  - Fixed atomcat information leak and DoS (CVE-2011-2526)

Also one bug was fixed :

  - fix bnc#702289 - suse manager pam ldap authentication
    fails

  - source CATALINA_HOME/bin/setenv.sh if exists"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-09/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=702289"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=706382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=706404"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat6 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/15");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"tomcat6-6.0.32-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"tomcat6-admin-webapps-6.0.32-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"tomcat6-docs-webapp-6.0.32-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"tomcat6-el-1_0-api-6.0.32-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"tomcat6-javadoc-6.0.32-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"tomcat6-jsp-2_1-api-6.0.32-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"tomcat6-lib-6.0.32-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"tomcat6-servlet-2_5-api-6.0.32-7.8.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"tomcat6-webapps-6.0.32-7.8.1") ) flag++;

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
