#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-883.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74853);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2009-2693", "CVE-2009-2901", "CVE-2009-2902", "CVE-2012-2733", "CVE-2012-3546", "CVE-2012-4431", "CVE-2012-5568", "CVE-2012-5885", "CVE-2012-5886", "CVE-2012-5887");

  script_name(english:"openSUSE Security Update : tomcat (openSUSE-SU-2012:1701-1)");
  script_summary(english:"Check for the openSUSE-2012-883 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - fix bnc#793394 - bypass of security constraints
    (CVE-2012-3546)

  - tomcat-CVE-2012-3546.patch
    http://svn.apache.org/viewvc?view=revision&revision=1377
    892

  - fix bnc#793391 - bypass of CSRF prevention filter
    (CVE-2012-4431)

  - tomcat-CVE-2012-4431.patch
    http://svn.apache.org/viewvc?view=revision&revision=1393
    088

  - document how to protect against slowloris DoS
    (CVE-2012-5568/bnc#791679) in README.SUSE

  - fixes bnc#791423 - cnonce tracking weakness
    (CVE-2012-5885) bnc#791424 - authentication caching
    weakness (CVE-2012-5886) bnc#791426 - stale nonce
    weakness (CVE-2012-5887)

  - tomcat-dont-parse-user-name-twice.patch
    http://svn.apache.org/viewvc?view=revision&revision=1366
    723

  - tomcat-CVE-2009-2693-CVE-2009-2901-CVE-2009-2902.patch
    http://svn.apache.org/viewvc?view=revision&revision=1377
    807

  - fix bnc#789406: HTTP NIO connector OOM DoS via a request
    with large headers (CVE-2012-2733)

  - http://svn.apache.org/viewvc?view=revision&revision=1350301

  - fix bnc#779538 - Tomcat7 default current workdir isn't
    /usr/share/tomcat"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-12/msg00062.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://svn.apache.org/viewvc?view=revision&revision=1350301"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://svn.apache.org/viewvc?view=revision&revision=1366723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://svn.apache.org/viewvc?view=revision&revision=1377807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://svn.apache.org/viewvc?view=revision&revision=1377892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://svn.apache.org/viewvc?view=revision&revision=1393088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=791423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=791424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=791426"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=791679"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=793391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=793394"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cwe_id(22, 264);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/18");
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

if ( rpm_check(release:"SUSE12.2", reference:"tomcat-7.0.27-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tomcat-admin-webapps-7.0.27-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tomcat-docs-webapp-7.0.27-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tomcat-el-2_2-api-7.0.27-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tomcat-javadoc-7.0.27-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tomcat-jsp-2_2-api-7.0.27-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tomcat-jsvc-7.0.27-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tomcat-lib-7.0.27-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tomcat-servlet-3_0-api-7.0.27-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"tomcat-webapps-7.0.27-2.9.1") ) flag++;

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
