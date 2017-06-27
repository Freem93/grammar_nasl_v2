#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-577.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75083);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-1872");

  script_name(english:"openSUSE Security Update : Mesa (openSUSE-SU-2013:1188-1)");
  script_summary(english:"Check for the openSUSE-2013-577 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mesa was updated to fix a security problem in the Intel drivers, where
potentially remote attackers via 3D models could inject code.

(CVE-2013-1872 - i965: fix problem with constant out of bounds access
(bnc #828007).)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-07/msg00046.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828007"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected Mesa packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libEGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libEGL-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libEGL1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libEGL1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libEGL1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libEGL1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGL-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGL1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGL1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGL1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGL1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLESv1_CM-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLESv1_CM-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLESv1_CM1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLESv1_CM1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLESv1_CM1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLESv1_CM1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLESv2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLESv2-2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLESv2-2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLESv2-2-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLESv2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLESv2-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLU-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLU-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLU1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLU1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLU1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libGLU1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libIndirectGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libIndirectGL-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libIndirectGL1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libIndirectGL1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libIndirectGL1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libIndirectGL1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libglapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libglapi-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libglapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libglapi0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libglapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:Mesa-libglapi0-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libOSMesa-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libOSMesa-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libOSMesa8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libOSMesa8-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libOSMesa8-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libOSMesa8-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libOSMesa9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libOSMesa9-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libOSMesa9-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libOSMesa9-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_nouveau");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_nouveau-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_nouveau-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_nouveau-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_r300");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_r300-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_r300-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_r300-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_r600");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_r600-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_r600-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_r600-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_softpipe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_softpipe-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_softpipe-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libXvMC_softpipe-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgbm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgbm-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgbm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgbm1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgbm1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgbm1-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_nouveau");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_nouveau-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_nouveau-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_nouveau-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_r300");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_r300-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_r300-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_r300-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_r600");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_r600-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_r600-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_r600-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_softpipe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_softpipe-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_softpipe-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvdpau_softpipe-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxatracker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxatracker1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libxatracker1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/05");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"Mesa-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-debuginfo-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-debugsource-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-devel-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-libEGL-devel-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-libEGL1-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-libEGL1-debuginfo-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-libGL-devel-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-libGL1-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-libGL1-debuginfo-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-libGLESv1_CM-devel-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-libGLESv1_CM1-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-libGLESv1_CM1-debuginfo-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-libGLESv2-2-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-libGLESv2-2-debuginfo-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-libGLESv2-devel-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-libGLU-devel-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-libGLU1-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-libGLU1-debuginfo-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-libIndirectGL1-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-libIndirectGL1-debuginfo-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-libglapi0-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"Mesa-libglapi0-debuginfo-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libOSMesa8-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libOSMesa8-debuginfo-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libXvMC_nouveau-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libXvMC_nouveau-debuginfo-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libXvMC_r300-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libXvMC_r300-debuginfo-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libXvMC_r600-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libXvMC_r600-debuginfo-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libXvMC_softpipe-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libXvMC_softpipe-debuginfo-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgbm-devel-0.0.0-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgbm1-0.0.0-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libgbm1-debuginfo-0.0.0-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libvdpau_nouveau-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libvdpau_nouveau-debuginfo-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libvdpau_r300-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libvdpau_r300-debuginfo-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libvdpau_r600-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libvdpau_r600-debuginfo-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libvdpau_softpipe-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libvdpau_softpipe-debuginfo-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxatracker-devel-1.0.0-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxatracker1-1.0.0-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"libxatracker1-debuginfo-1.0.0-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-debuginfo-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-devel-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-libEGL-devel-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-libEGL1-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-libEGL1-debuginfo-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-libGL-devel-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-libGL1-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-libGL1-debuginfo-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-libGLESv1_CM-devel-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-libGLESv1_CM1-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-libGLESv1_CM1-debuginfo-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-libGLESv2-2-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-libGLESv2-2-debuginfo-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-libGLESv2-devel-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-libGLU-devel-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-libGLU1-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-libGLU1-debuginfo-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-libIndirectGL1-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-libIndirectGL1-debuginfo-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-libglapi0-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"Mesa-libglapi0-debuginfo-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libOSMesa8-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libOSMesa8-debuginfo-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libXvMC_nouveau-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libXvMC_nouveau-debuginfo-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libXvMC_r300-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libXvMC_r300-debuginfo-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libXvMC_r600-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libXvMC_r600-debuginfo-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libXvMC_softpipe-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libXvMC_softpipe-debuginfo-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libgbm-devel-32bit-0.0.0-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libgbm1-32bit-0.0.0-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libgbm1-debuginfo-32bit-0.0.0-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libvdpau_nouveau-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libvdpau_nouveau-debuginfo-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libvdpau_r300-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libvdpau_r300-debuginfo-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libvdpau_r600-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libvdpau_r600-debuginfo-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libvdpau_softpipe-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"libvdpau_softpipe-debuginfo-32bit-8.0.4-20.27.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-debuginfo-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-debugsource-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-devel-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-libEGL-devel-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-libEGL1-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-libEGL1-debuginfo-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-libGL-devel-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-libGL1-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-libGL1-debuginfo-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-libGLESv1_CM-devel-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-libGLESv1_CM1-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-libGLESv1_CM1-debuginfo-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-libGLESv2-2-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-libGLESv2-2-debuginfo-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-libGLESv2-devel-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-libIndirectGL-devel-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-libIndirectGL1-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-libIndirectGL1-debuginfo-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-libglapi-devel-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-libglapi0-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"Mesa-libglapi0-debuginfo-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libOSMesa-devel-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libOSMesa9-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libOSMesa9-debuginfo-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXvMC_nouveau-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXvMC_nouveau-debuginfo-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXvMC_r300-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXvMC_r300-debuginfo-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXvMC_r600-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXvMC_r600-debuginfo-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXvMC_softpipe-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libXvMC_softpipe-debuginfo-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgbm-devel-0.0.0-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgbm1-0.0.0-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libgbm1-debuginfo-0.0.0-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libvdpau_nouveau-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libvdpau_nouveau-debuginfo-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libvdpau_r300-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libvdpau_r300-debuginfo-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libvdpau_r600-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libvdpau_r600-debuginfo-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libvdpau_softpipe-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libvdpau_softpipe-debuginfo-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxatracker-devel-1.0.0-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxatracker1-1.0.0-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"libxatracker1-debuginfo-1.0.0-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"Mesa-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"Mesa-debuginfo-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"Mesa-devel-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"Mesa-libEGL-devel-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"Mesa-libEGL1-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"Mesa-libEGL1-debuginfo-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"Mesa-libGL-devel-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"Mesa-libGL1-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"Mesa-libGL1-debuginfo-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"Mesa-libGLESv1_CM-devel-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"Mesa-libGLESv1_CM1-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"Mesa-libGLESv1_CM1-debuginfo-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"Mesa-libGLESv2-2-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"Mesa-libGLESv2-2-debuginfo-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"Mesa-libGLESv2-devel-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"Mesa-libIndirectGL-devel-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"Mesa-libIndirectGL1-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"Mesa-libIndirectGL1-debuginfo-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"Mesa-libglapi-devel-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"Mesa-libglapi0-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"Mesa-libglapi0-debuginfo-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libOSMesa-devel-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libOSMesa9-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libOSMesa9-debuginfo-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXvMC_nouveau-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXvMC_nouveau-debuginfo-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXvMC_r300-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXvMC_r300-debuginfo-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXvMC_r600-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXvMC_r600-debuginfo-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXvMC_softpipe-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libXvMC_softpipe-debuginfo-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libgbm-devel-32bit-0.0.0-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libgbm1-32bit-0.0.0-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libgbm1-debuginfo-32bit-0.0.0-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libvdpau_nouveau-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libvdpau_nouveau-debuginfo-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libvdpau_r300-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libvdpau_r300-debuginfo-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libvdpau_r600-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libvdpau_r600-debuginfo-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libvdpau_softpipe-32bit-9.0.2-34.20.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"libvdpau_softpipe-debuginfo-32bit-9.0.2-34.20.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mesa");
}
