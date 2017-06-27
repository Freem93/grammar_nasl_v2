#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-222.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74929);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_cve_id("CVE-2013-2492");
  script_bugtraq_id(58393);
  script_osvdb_id(91044);

  script_name(english:"openSUSE Security Update : firebird (openSUSE-SU-2013:0496-1)");
  script_summary(english:"Check for the openSUSE-2013-222 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a bug which allows an unauthenticated remote
attacker to cause a stack overflow in server code, resulting in either
server crash or even code execution as the user running firebird."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-03/msg00067.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808268"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firebird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firebird Relational Database CNCT Group Number Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-classic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-classic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-classic-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-superserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:firebird-superserver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfbclient2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfbclient2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfbclient2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfbclient2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfbclient2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfbembed-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfbembed2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfbembed2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfbembed2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfbembed2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfbembed2_5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfbembed2_5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"firebird-2.1.3.18185.0-22.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"firebird-classic-2.1.3.18185.0-22.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"firebird-classic-debuginfo-2.1.3.18185.0-22.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"firebird-debuginfo-2.1.3.18185.0-22.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"firebird-debugsource-2.1.3.18185.0-22.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"firebird-devel-2.1.3.18185.0-22.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"firebird-devel-debuginfo-2.1.3.18185.0-22.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"firebird-filesystem-2.1.3.18185.0-22.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"firebird-superserver-2.1.3.18185.0-22.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"firebird-superserver-debuginfo-2.1.3.18185.0-22.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libfbclient2-2.1.3.18185.0-22.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libfbclient2-debuginfo-2.1.3.18185.0-22.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libfbembed2-2.1.3.18185.0-22.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"libfbembed2-debuginfo-2.1.3.18185.0-22.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfbclient2-32bit-2.1.3.18185.0-22.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfbclient2-debuginfo-32bit-2.1.3.18185.0-22.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfbembed2-32bit-2.1.3.18185.0-22.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", cpu:"x86_64", reference:"libfbembed2-debuginfo-32bit-2.1.3.18185.0-22.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"firebird-2.5.2.26539-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"firebird-classic-2.5.2.26539-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"firebird-classic-debuginfo-2.5.2.26539-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"firebird-classic-debugsource-2.5.2.26539-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"firebird-debuginfo-2.5.2.26539-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"firebird-debugsource-2.5.2.26539-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"firebird-devel-2.5.2.26539-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"firebird-superserver-2.5.2.26539-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"firebird-superserver-debuginfo-2.5.2.26539-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libfbclient2-2.5.2.26539-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libfbclient2-debuginfo-2.5.2.26539-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libfbclient2-devel-2.5.2.26539-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libfbembed-devel-2.5.2.26539-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libfbembed2_5-2.5.2.26539-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libfbembed2_5-debuginfo-2.5.2.26539-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"firebird-32bit-2.5.2.26539-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"firebird-debuginfo-32bit-2.5.2.26539-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libfbclient2-32bit-2.5.2.26539-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libfbclient2-debuginfo-32bit-2.5.2.26539-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"firebird-2.5.2.26539-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"firebird-classic-2.5.2.26539-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"firebird-classic-debuginfo-2.5.2.26539-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"firebird-classic-debugsource-2.5.2.26539-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"firebird-debuginfo-2.5.2.26539-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"firebird-debugsource-2.5.2.26539-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"firebird-devel-2.5.2.26539-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"firebird-superserver-2.5.2.26539-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"firebird-superserver-debuginfo-2.5.2.26539-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfbclient2-2.5.2.26539-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfbclient2-debuginfo-2.5.2.26539-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfbclient2-devel-2.5.2.26539-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfbembed-devel-2.5.2.26539-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfbembed2_5-2.5.2.26539-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libfbembed2_5-debuginfo-2.5.2.26539-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"firebird-32bit-2.5.2.26539-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"firebird-debuginfo-32bit-2.5.2.26539-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libfbclient2-32bit-2.5.2.26539-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libfbclient2-debuginfo-32bit-2.5.2.26539-2.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firebird / firebird-classic / firebird-classic-debuginfo / etc");
}
