#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-164.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74906);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_cve_id("CVE-2013-0169", "CVE-2013-1486");
  script_osvdb_id(89848, 90353);

  script_name(english:"openSUSE Security Update : java-1_6_0-openjdk (openSUSE-SU-2013:0375-1)");
  script_summary(english:"Check for the openSUSE-2013-164 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"java-1_6_0-openjdk was updated to IcedTea 1.12.3 (bnc#804654)
containing security and bugfixes :

  - Security fixes

  - S8006446: Restrict MBeanServer access (CVE-2013-1486)

  - S8006777: Improve TLS handling of invalid messages Lucky
    13 (CVE-2013-0169)

  - S8007688: Blacklist known bad certificate (issued by
    DigiCert)

  - Backports

  - S8007393: Possible race condition after JDK-6664509

  - S8007611: logging behavior in applet changed

  - Bug fixes

  - PR1319: Support GIF lib v5."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-03/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804654"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1_6_0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-demo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:java-1_6_0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
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

if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-1.6.0.0_b27.1.12.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-debuginfo-1.6.0.0_b27.1.12.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-debugsource-1.6.0.0_b27.1.12.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-demo-1.6.0.0_b27.1.12.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-demo-debuginfo-1.6.0.0_b27.1.12.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-devel-1.6.0.0_b27.1.12.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-devel-debuginfo-1.6.0.0_b27.1.12.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-javadoc-1.6.0.0_b27.1.12.3-28.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"java-1_6_0-openjdk-src-1.6.0.0_b27.1.12.3-28.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1_6_0-openjdk");
}
