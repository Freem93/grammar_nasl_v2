#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-633.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75107);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_cve_id("CVE-2012-3544", "CVE-2013-1976", "CVE-2013-2067");
  script_osvdb_id(93252, 93253, 95550);

  script_name(english:"openSUSE Security Update : tomcat (openSUSE-SU-2013:1307-1)");
  script_summary(english:"Check for the openSUSE-2013-633 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tomcat was updated to fix security issues and bug: CVE-2013-1976:
Avoid a potential symlink race during startup of the tomcat server,
where a local attacker that gaine access to the tomcat chroot could
escalate privileges to root.

CVE-2013-2067:
java/org/apache/catalina/authenticator/FormAuthenticator.java in the
form authentication feature in Apache Tomcat did not properly handle
the relationships between authentication requirements and sessions,
which allows remote attackers to inject a request into a session by
sending this request during completion of the login form, a variant of
a session fixation attack.

CVE-2012-3544: Tomcat were affected by a chunked transfer encoding
extension size denial of service vulnerability.

Also the following bug was fixed :

  - Fix tomcat init scripts generating malformed classpath
    (http://youtrack.jetbrains.com/issue/JT-18545)
    bnc#804992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-08/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://youtrack.jetbrains.com/issue/JT-18545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=768772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804992"
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
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831119"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"tomcat-7.0.27-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tomcat-admin-webapps-7.0.27-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tomcat-docs-webapp-7.0.27-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tomcat-el-2_2-api-7.0.27-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tomcat-javadoc-7.0.27-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tomcat-jsp-2_2-api-7.0.27-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tomcat-jsvc-7.0.27-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tomcat-lib-7.0.27-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tomcat-servlet-3_0-api-7.0.27-2.26.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tomcat-webapps-7.0.27-2.26.1") ) flag++;

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
