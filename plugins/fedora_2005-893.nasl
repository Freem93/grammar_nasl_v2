#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-893.
#

include("compat.inc");

if (description)
{
  script_id(19739);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:38:06 $");

  script_cve_id("CVE-2005-2495");
  script_xref(name:"FEDORA", value:"2005-893");

  script_name(english:"Fedora Core 3 : xorg-x11-6.8.2-1.FC3.45 (2005-893)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xorg-x11 packages that fix several integer overflows, various
bugs, are now available for Fedora Core 3.

X.Org X11 is an implementation of the X Window System, which provides
the core functionality for the Linux graphical desktop.

Several integer overflow bugs were found in the way X.Org X11 code
parses pixmap images. It is possible for a user to gain elevated
privileges by loading a specially crafted pixmap image. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-2495 to this issue.

Additionally, this update contains :

  - Support for some newer models of Intel i945 video
    chipsets.

  - A change to the X server to make it use linux PCI config
    space access methods instead of directly touching the
    PCI config space registers itself. This prevents the X
    server from causing hardware lockups due accessing PCI
    config space at the same time the kernel has it locked.
    This is the latest revision of the PCI config space
    access patches, which fix a few regressions discovered
    on some hardware with previous patches.

  - A fix for a memory leak in the X server's shadow
    framebuffer code.

  - A problem with the Dutch keyboard layout has been
    resolved.

  - The open source 'nv' driver for Nvidia hardware has been
    updated to the latest version. Additionally, a
    workaround has been added to the driver to disable known
    unstable acceleration primitives on some GeForce
    6200/6600/6800 models.

  - Several bugs have been fixed in the Xnest X server.

  - DRI is now enabled by default on all ATI Radeon hardware
    except for the Radeon 7000/Radeon VE chipsets, which is
    known to be unstable for many users currently when DRI
    is enabled. Radeon 7000 users can re-enable DRI if
    desired by using Option 'DRI' in the device section of
    the config file, with the understanding that we consider
    it unstable currently.

  - Added missing libFS.so and libGLw.so symlinks to the
    xorg-x11-devel package, which were inadvertently left
    out, causing apps to link to the static versions of
    these libraries.

  - Fix xfs.init 'fonts.dir: No such file or directory'
    errors

A number of other issues have also been resolved. Please consult the
xorg-x11 rpm changelog for a detailed list.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-September/001380.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99c29075"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-Mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-Mesa-libGLU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-deprecated-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-deprecated-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-font-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-twm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-xauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-xdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-xfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 3.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC3", reference:"xorg-x11-6.8.2-1.FC3.45")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-Mesa-libGL-6.8.2-1.FC3.45")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-Mesa-libGLU-6.8.2-1.FC3.45")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-Xdmx-6.8.2-1.FC3.45")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-Xnest-6.8.2-1.FC3.45")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-Xvfb-6.8.2-1.FC3.45")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-deprecated-libs-6.8.2-1.FC3.45")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.FC3.45")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-devel-6.8.2-1.FC3.45")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-doc-6.8.2-1.FC3.45")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-font-utils-6.8.2-1.FC3.45")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-libs-6.8.2-1.FC3.45")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-sdk-6.8.2-1.FC3.45")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-tools-6.8.2-1.FC3.45")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-twm-6.8.2-1.FC3.45")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-xauth-6.8.2-1.FC3.45")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-xdm-6.8.2-1.FC3.45")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-xfs-6.8.2-1.FC3.45")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11 / xorg-x11-Mesa-libGL / xorg-x11-Mesa-libGLU / etc");
}
