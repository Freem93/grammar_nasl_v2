#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-632.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75106);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-1976", "CVE-2013-2071");

  script_name(english:"openSUSE Security Update : tomcat (openSUSE-SU-2013:1306-1)");
  script_summary(english:"Check for the openSUSE-2013-632 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tomcat was updated to fix two security issues: CVE-2013-1976: Avoid a
potential symlink race during startup of the tomcat server, where a
local attacker that gaine access to the tomcat chroot could escalate
privileges to root.

CVE-2013-2071:
java/org/apache/catalina/core/AsyncContextImpl.java in
Apache Tomcat 7.x did not properly handle the throwing of a
RuntimeException in an AsyncListener in an application,
which allows context-dependent attackers to obtain sensitive
request information intended for other applications in
opportunistic circumstances via an application that records
the requests that it processes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-08/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831117"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-el-2_2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-jsp-2_2-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-servlet-3_0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/03");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"tomcat-7.0.35-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"tomcat-admin-webapps-7.0.35-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"tomcat-docs-webapp-7.0.35-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"tomcat-el-2_2-api-7.0.35-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"tomcat-javadoc-7.0.35-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"tomcat-jsp-2_2-api-7.0.35-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"tomcat-jsvc-7.0.35-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"tomcat-lib-7.0.35-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"tomcat-servlet-3_0-api-7.0.35-2.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"tomcat-webapps-7.0.35-2.33.1") ) flag++;

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
