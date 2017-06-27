#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-498.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74707);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-3382");
  script_osvdb_id(83683);

  script_name(english:"openSUSE Security Update : mono-web (openSUSE-SU-2012:0974-1)");
  script_summary(english:"Check for the openSUSE-2012-498 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mono was updated to fix :

A cross site scripting attack in the System.Web class 'forbidden
extensions' filtering was fixed. (CVE-2012-3382)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-08/msg00017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=769799"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mono-web packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ibm-data-db2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmono-2_0-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmono-2_0-1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmono-2_0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmonosgen-2_0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmonosgen-2_0-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmonosgen-2_0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-complete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-core-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-data-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-data-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-data-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-locale-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-mvc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-nunit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-wcf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-winforms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mono-winfxcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:monodoc-core");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.4|SUSE12\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"ibm-data-db2-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmono-2_0-1-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmono-2_0-1-debuginfo-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmono-2_0-devel-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmonosgen-2_0-0-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmonosgen-2_0-0-debuginfo-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"libmonosgen-2_0-devel-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mono-complete-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mono-core-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mono-core-debuginfo-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mono-core-debugsource-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mono-data-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mono-data-oracle-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mono-data-postgresql-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mono-data-sqlite-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mono-devel-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mono-devel-debuginfo-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mono-extras-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mono-locale-extras-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mono-mvc-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mono-nunit-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mono-wcf-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mono-web-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mono-winforms-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"mono-winfxcore-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"monodoc-core-2.8.2-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"ibm-data-db2-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmono-2_0-1-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmono-2_0-1-debuginfo-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmono-2_0-devel-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmonosgen-2_0-0-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmonosgen-2_0-0-debuginfo-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libmonosgen-2_0-devel-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mono-complete-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mono-core-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mono-core-debuginfo-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mono-core-debugsource-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mono-data-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mono-data-oracle-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mono-data-postgresql-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mono-data-sqlite-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mono-devel-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mono-devel-debuginfo-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mono-extras-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mono-locale-extras-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mono-mvc-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mono-nunit-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mono-wcf-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mono-web-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mono-winforms-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"mono-winfxcore-2.10.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"monodoc-core-2.10.6-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mono-web");
}
