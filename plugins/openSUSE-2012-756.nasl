#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-756.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74801);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_cve_id("CVE-2009-4020", "CVE-2010-3873", "CVE-2010-4164", "CVE-2010-4249", "CVE-2011-1083", "CVE-2011-1173", "CVE-2011-2517", "CVE-2011-2700", "CVE-2011-2909", "CVE-2011-2928", "CVE-2011-3619", "CVE-2011-3638", "CVE-2011-4077", "CVE-2011-4086", "CVE-2011-4110", "CVE-2011-4330", "CVE-2012-0038", "CVE-2012-0044", "CVE-2012-0207", "CVE-2012-1090", "CVE-2012-1097", "CVE-2012-1146", "CVE-2012-2119", "CVE-2012-2123", "CVE-2012-2136", "CVE-2012-2663");
  script_osvdb_id(60795, 69017, 69527, 70291, 71265, 73298, 74658, 74823, 74881, 74882, 76641, 76666, 76793, 77450, 77683, 78225, 78226, 78227, 79097, 79672, 80554, 80605, 81812, 82459, 83105, 83194, 83205);

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2012:1439-1)");
  script_summary(english:"Check for the openSUSE-2012-756 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 11.4 kernel was updated to fix various bugs and security
issues.

This is the final update of the 2.6.37 kernel of openSUSE 11.4."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-11/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=466279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=651219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=653260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=655696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=676204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=681639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=683671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=689860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=703410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=707332"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=711941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=713430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=714455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=717209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=717749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=721366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=726045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=726600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=729247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=730118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=731673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=732908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=734056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=737624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=738644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=740448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=740703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=740745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=746980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=748859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=749569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=755546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=756203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=756840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758260"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=759545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=760902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=765102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=765320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=769408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=769784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=769896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=781134"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vmi-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/31");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-base-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-base-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-debugsource-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-devel-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-debug-devel-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-base-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-base-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-debugsource-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-devel-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-default-devel-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-base-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-base-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-debugsource-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-devel-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-desktop-devel-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-devel-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-base-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-base-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-debugsource-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-devel-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-devel-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-extra-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-ec2-extra-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-base-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-base-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-debugsource-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-devel-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-pae-devel-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-source-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-source-vanilla-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-syms-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-base-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-base-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-debugsource-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-devel-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-trace-devel-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-base-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-base-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-debugsource-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-devel-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vanilla-devel-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-base-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-base-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-debugsource-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-devel-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-vmi-devel-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-base-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-base-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-debugsource-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-devel-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"kernel-xen-devel-debuginfo-2.6.37.6-24.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-1.2-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-debuginfo-1.2-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-debugsource-1.2-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-kmp-default-1.2_k2.6.37.6_24-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-kmp-default-debuginfo-1.2_k2.6.37.6_24-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-kmp-desktop-1.2_k2.6.37.6_24-6.19.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"preload-kmp-desktop-debuginfo-1.2_k2.6.37.6_24-6.19.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
