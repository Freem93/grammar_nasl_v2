#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-384.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(90136);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/11/04 15:55:10 $");

  script_cve_id("CVE-2015-5174", "CVE-2015-5345", "CVE-2015-5346", "CVE-2015-5351", "CVE-2016-0706", "CVE-2016-0714", "CVE-2016-0763");

  script_name(english:"openSUSE Security Update : tomcat (openSUSE-2016-384)");
  script_summary(english:"Check for the openSUSE-2016-384 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for tomcat fixes the following issues :

Tomcat 8 was updated from 8.0.23 to 8.0.32, to fix bugs and security
issues.

Fixed security issues :

  - CVE-2015-5174: Directory traversal vulnerability in
    RequestUtil.java in Apache Tomcat allowed remote
    authenticated users to bypass intended SecurityManager
    restrictions and list a parent directory via a /..
    (slash dot dot) in a pathname used by a web application
    in a getResource, getResourceAsStream, or
    getResourcePaths call, as demonstrated by the
    $CATALINA_BASE/webapps directory. (bsc#967967)

  - CVE-2015-5346: Session fixation vulnerability in Apache
    Tomcat when different session settings are used for
    deployments of multiple versions of the same web
    application, might have allowed remote attackers to
    hijack web sessions by leveraging use of a
    requestedSessionSSL field for an unintended request,
    related to CoyoteAdapter.java and Request.java.
    (bsc#967814)

  - CVE-2015-5345: The Mapper component in Apache Tomcat
    processes redirects before considering security
    constraints and Filters, which allowed remote attackers
    to determine the existence of a directory via a URL that
    lacks a trailing / (slash) character. (bsc#967965)

  - CVE-2015-5351: The (1) Manager and (2) Host Manager
    applications in Apache Tomcat established sessions and
    send CSRF tokens for arbitrary new requests, which
    allowed remote attackers to bypass a CSRF protection
    mechanism by using a token. (bsc#967812)

  - CVE-2016-0706: Apache Tomcat did not place
    org.apache.catalina.manager.StatusManagerServlet on the
    org/apache/catalina/core/RestrictedServlets.properties
    list, which allowed remote authenticated users to bypass
    intended SecurityManager restrictions and read arbitrary
    HTTP requests, and consequently discover session ID
    values, via a crafted web application. (bsc#967815)

  - CVE-2016-0714: The session-persistence implementation in
    Apache Tomcat mishandled session attributes, which
    allowed remote authenticated users to bypass intended
    SecurityManager restrictions and execute arbitrary code
    in a privileged context via a web application that
    places a crafted object in a session. (bsc#967964)

  - CVE-2016-0763: The setGlobalContext method in
    org/apache/naming/factory/ResourceLinkFactory.java in
    Apache Tomcat did not consider whether
    ResourceLinkFactory.setGlobalContext callers are
    authorized, which allowed remote authenticated users to
    bypass intended SecurityManager restrictions and read or
    write to arbitrary application data, or cause a denial
    of service (application disruption), via a web
    application that sets a crafted global context.
    (bsc#967966)

The full changes can be read on:
http://tomcat.apache.org/tomcat-8.0-doc/changelog.html

This update was imported from the SUSE:SLE-12-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://tomcat.apache.org/tomcat-8.0-doc/changelog.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967964"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967965"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967967"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-el-3_0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-jsp-2_3-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-jsvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-servlet-3_1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"tomcat-8.0.32-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tomcat-admin-webapps-8.0.32-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tomcat-docs-webapp-8.0.32-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tomcat-el-3_0-api-8.0.32-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tomcat-embed-8.0.32-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tomcat-javadoc-8.0.32-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tomcat-jsp-2_3-api-8.0.32-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tomcat-jsvc-8.0.32-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tomcat-lib-8.0.32-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tomcat-servlet-3_1-api-8.0.32-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"tomcat-webapps-8.0.32-5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat / tomcat-admin-webapps / tomcat-docs-webapp / etc");
}
