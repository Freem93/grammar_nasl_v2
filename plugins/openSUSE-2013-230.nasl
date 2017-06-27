#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-230.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74933);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/08/06 14:06:07 $");

  script_cve_id("CVE-2013-0809", "CVE-2013-1493");
  script_osvdb_id(90737, 90837);

  script_name(english:"openSUSE Security Update : java-1_7_0-openjdk (openSUSE-SU-2013:0509-1)");
  script_summary(english:"Check for the openSUSE-2013-230 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"java-1_7_0-openjdk was updated to icedtea-2.3.7 (bnc#809386) :

  - Security fixes

  - S8007014, CVE-2013-0809: Improve image handling

  - S8007675, CVE-2013-1493: Improve color conversion

  - Backports

  - S8002344: Krb5LoginModule config class does not return
    proper KDC list from DNS

  - S8004344: Fix a crash in ToolkitErrorHandler() in
    XlibWrapper.c

  - S8006179: JSR292 MethodHandles lookup with interface
    using findVirtual()

  - S8006882: Proxy generated classes in sun.proxy package
    breaks JMockit

  - Bug fixes

  - PR1303: Correct #ifdef to #if

  - PR1340: Simplify the rhino class rewriter to avoid use
    of concurrency

  - Revert 7017193 and add the missing free call, until a
    better fix is ready."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-03/msg00078.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809386"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_7_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java CMM Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_7_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-1.7.0.6-3.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.6-3.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-debugsource-1.7.0.6-3.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-demo-1.7.0.6-3.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.6-3.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-devel-1.7.0.6-3.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.6-3.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-javadoc-1.7.0.6-3.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"java-1_7_0-openjdk-src-1.7.0.6-3.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-1.7.0.6-8.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-debuginfo-1.7.0.6-8.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-debugsource-1.7.0.6-8.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-demo-1.7.0.6-8.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-demo-debuginfo-1.7.0.6-8.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-devel-1.7.0.6-8.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-devel-debuginfo-1.7.0.6-8.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-javadoc-1.7.0.6-8.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"java-1_7_0-openjdk-src-1.7.0.6-8.8.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_7_0-openjdk");
}
