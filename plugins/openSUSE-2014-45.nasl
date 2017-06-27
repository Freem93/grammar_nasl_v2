#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-45.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75391);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/09 15:44:48 $");

  script_cve_id("CVE-2013-6462");
  script_bugtraq_id(64694);
  script_osvdb_id(101842);

  script_name(english:"openSUSE Security Update : libXfont (openSUSE-SU-2014:0073-1)");
  script_summary(english:"Check for the openSUSE-2014-45 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"-
    U_CVE-2013-6462-unlimited-sscanf-overflows-stack-buffe.p
    atch 

  - unlimited sscanf overflows stack buffer in
    bdfReadCharacters() (CVE-2013-6462, bnc#854915)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-01/msg00050.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=854915"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libXfont packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXfont1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/08");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"libXfont-debugsource-1.4.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libXfont-devel-1.4.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libXfont1-1.4.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libXfont1-debuginfo-1.4.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libXfont-devel-32bit-1.4.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libXfont1-32bit-1.4.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libXfont1-debuginfo-32bit-1.4.5-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXfont-debugsource-1.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXfont-devel-1.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXfont1-1.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXfont1-debuginfo-1.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXfont-devel-32bit-1.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXfont1-32bit-1.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXfont1-debuginfo-32bit-1.4.5-4.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libXfont-debugsource-1.4.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libXfont-devel-1.4.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libXfont1-1.4.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libXfont1-debuginfo-1.4.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libXfont-devel-32bit-1.4.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libXfont1-32bit-1.4.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"libXfont1-debuginfo-32bit-1.4.6-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libXfont-debugsource / libXfont-devel / libXfont-devel-32bit / etc");
}
