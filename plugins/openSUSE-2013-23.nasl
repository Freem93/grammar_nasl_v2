#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-23.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74938);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_cve_id("CVE-2012-4431", "CVE-2012-4534");
  script_osvdb_id(88093, 88095);

  script_name(english:"openSUSE Security Update : tomcat6 (openSUSE-SU-2013:0161-1)");
  script_summary(english:"Check for the openSUSE-2013-23 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - fix bnc#794548 - denial of service (CVE-2012-4534)

  - apache-tomcat-CVE-2012-4534.patch fixes apache#53138,
    apache#52858
    http://svn.apache.org/viewvc?view=rev&rev=1372035

  - fix a minor issue in apache-tomcat-CVE-2012-4431.patch
    use the already initialized session variable instead of
    an another call req.getSesssion()"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-01/msg00051.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://svn.apache.org/viewvc?view=rev&rev=1372035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=794548"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat6 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtcnative-1-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtcnative-1-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtcnative-1-0-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtcnative-1-0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-el-1_0-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-jsp-2_1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-servlet-2_5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"libtcnative-1-0-1.3.3-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtcnative-1-0-debuginfo-1.3.3-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtcnative-1-0-debugsource-1.3.3-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libtcnative-1-0-devel-1.3.3-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"tomcat6-6.0.33-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"tomcat6-admin-webapps-6.0.33-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"tomcat6-docs-webapp-6.0.33-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"tomcat6-el-1_0-api-6.0.33-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"tomcat6-javadoc-6.0.33-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"tomcat6-jsp-2_1-api-6.0.33-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"tomcat6-lib-6.0.33-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"tomcat6-servlet-2_5-api-6.0.33-3.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"tomcat6-webapps-6.0.33-3.11.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtcnative-1-0 / libtcnative-1-0-debuginfo / etc");
}
