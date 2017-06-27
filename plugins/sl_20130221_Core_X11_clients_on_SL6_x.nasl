#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(65563);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/03/24 23:40:37 $");

  script_cve_id("CVE-2011-2504");

  script_name(english:"Scientific Linux Security Update : Core X11 clients on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that the x11perfcomp utility included the current working
directory in its PATH environment variable. Running x11perfcomp in an
attacker- controlled directory would cause arbitrary code execution
with the privileges of the user running x11perfcomp. (CVE-2011-2504)

Also with this update, the xorg-x11-utils and xorg-x11-server-utils
packages have been upgraded to upstream version 7.5, and the
xorg-x11-apps package to upstream version 7.6, which provides a number
of bug fixes and enhancements over the previous versions.

*xorg ABI change With this update there is a change in the X.org ABI
for the video drivers. This change will require compatible drivers.
Anyone using the drivers shipped with SL should have no problems.
Anyone using drivers from an external source - such as nVidia, ATI, or
ELRepo should ensure a compatible driver is loaded. Please ensure you
are on the most recent compatible driver before updating the system.
--"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=4767
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90ddb711"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"libX11-1.5.0-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libX11-common-1.5.0-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libX11-devel-1.5.0-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXScrnSaver-1.2.2-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXScrnSaver-devel-1.2.2-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXau-1.0.6-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXau-devel-1.0.6-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXaw-1.0.11-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXaw-devel-1.0.11-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXcomposite-0.4.3-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXcomposite-devel-0.4.3-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXcursor-1.1.13-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXcursor-devel-1.1.13-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXdamage-1.1.3-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXdamage-devel-1.1.3-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXdmcp-1.1.1-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXdmcp-devel-1.1.1-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXevie-1.0.3-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXevie-devel-1.0.3-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXext-1.3.1-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXext-devel-1.3.1-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXfixes-5.0-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXfixes-devel-5.0-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXfont-1.4.5-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXfont-devel-1.4.5-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXft-2.3.1-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXft-devel-2.3.1-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXi-1.6.1-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXi-devel-1.6.1-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXinerama-1.1.2-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXinerama-devel-1.1.2-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXmu-1.1.1-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXmu-devel-1.1.1-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXpm-3.5.10-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXpm-devel-3.5.10-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXrandr-1.4.0-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXrandr-devel-1.4.0-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXrender-0.9.7-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXrender-devel-0.9.7-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXres-1.0.6-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXres-devel-1.0.6-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXt-1.1.3-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXt-devel-1.1.3-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXtst-1.2.1-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXtst-devel-1.2.1-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXv-1.0.7-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXv-devel-1.0.7-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXvMC-1.0.7-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXvMC-devel-1.0.7-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXxf86dga-1.1.3-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXxf86dga-devel-1.1.3-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXxf86misc-1.0.3-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXxf86misc-devel-1.0.3-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXxf86vm-1.1.2-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXxf86vm-devel-1.1.2-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libpciaccess-0.13.1-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libpciaccess-devel-0.13.1-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libxcb-1.8.1-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libxcb-devel-1.8.1-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libxcb-doc-1.8.1-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libxcb-python-1.8.1-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mesa-demos-9.0-0.7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mesa-dri-drivers-9.0-0.7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mesa-dri-filesystem-9.0-0.7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mesa-dri1-drivers-7.11-8.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mesa-libGL-9.0-0.7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mesa-libGL-devel-9.0-0.7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mesa-libGLU-9.0-0.7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mesa-libGLU-devel-9.0-0.7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mesa-libOSMesa-9.0-0.7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mesa-libOSMesa-devel-9.0-0.7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mtdev-1.1.2-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"mtdev-devel-1.1.2-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pixman-0.26.2-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pixman-devel-0.26.2-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xcb-proto-1.7-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-apps-7.6-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-apps-debuginfo-7.6-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-docs-1.3-6.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drivers-7.3-13.4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-acecad-1.5.0-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-aiptek-1.4.1-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-apm-1.2.5-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-ast-0.97.0-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-ati-6.99.99-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-ati-firmware-6.99.99-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-cirrus-1.5.1-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-dummy-0.3.6-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-elographics-1.4.1-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-evdev-2.7.3-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-evdev-devel-2.7.3-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-fbdev-0.4.3-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-fpit-1.4.0-5.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"xorg-x11-drv-geode-2.11.13-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-glint-1.2.8-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-hyperpen-1.4.1-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-i128-1.3.6-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-i740-1.3.4-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-intel-2.20.2-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-intel-devel-2.20.2-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-keyboard-1.6.2-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-mach64-6.9.3-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-mga-1.6.1-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-modesetting-0.5.0-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-mouse-1.8.1-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-mouse-devel-1.8.1-7.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-mutouch-1.3.0-4.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"xorg-x11-drv-neomagic-1.2.7-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-nouveau-1.0.1-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-nv-2.1.20-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-openchrome-0.3.0-3.20120806git.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-openchrome-devel-0.3.0-3.20120806git.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-penmount-1.5.0-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-qxl-0.1.0-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-r128-6.9.1-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-rendition-4.2.5-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-s3virge-1.10.6-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-savage-2.3.6-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-siliconmotion-1.7.7-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-sis-0.10.7-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-sisusb-0.9.6-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-synaptics-1.6.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-synaptics-devel-1.6.2-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-tdfx-1.4.5-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-trident-1.3.6-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-v4l-0.2.0-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-vesa-2.3.2-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-vmmouse-12.9.0-10.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-vmware-12.0.2-3.20120718gite5ac80d8f.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-void-1.4.0-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-voodoo-1.2.5-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-wacom-0.16.1-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-wacom-devel-0.16.1-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-drv-xgi-1.6.0-18.20121114git.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-proto-devel-7.6-25.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xdmx-1.13.0-11.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xephyr-1.13.0-11.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xnest-1.13.0-11.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xorg-1.13.0-11.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xvfb-1.13.0-11.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-common-1.13.0-11.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-devel-1.13.0-11.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-source-1.13.0-11.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-utils-7.5-13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-utils-debuginfo-7.5-13.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-util-macros-1.17-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-utils-7.5-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-utils-debuginfo-7.5-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-xkb-extras-7.7-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-xkb-utils-7.7-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-xkb-utils-devel-7.7-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-xtrans-devel-1.2.7-2.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
