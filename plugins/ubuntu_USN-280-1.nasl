#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-280-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21374);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/26 16:22:51 $");

  script_cve_id("CVE-2006-1526");
  script_osvdb_id(25191);
  script_xref(name:"USN", value:"280-1");

  script_name(english:"Ubuntu 5.04 / 5.10 : xorg vulnerability (USN-280-1)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Render extension of the X.org server incorrectly calculated the
size of a memory buffer, which led to a buffer overflow. A local
attacker could exploit this to crash the X server or even execute
arbitrary code with root privileges.

Note that Tenable Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:lbxproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdmx-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdmx1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdmx1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdps-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdps1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libdps1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfs6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libfs6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libice6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libice6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsm6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libsm6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx11-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx11-6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libx11-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxau-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxau6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxau6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxaw6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxaw6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxaw6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxaw7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxaw7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxaw7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxaw8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxaw8-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxaw8-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxcomposite-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxcomposite1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxcomposite1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxdamage-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxdamage1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxdamage1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxdmcp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxdmcp6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxdmcp6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxevie-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxevie1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxevie1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxext-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxext6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxext6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxfixes-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxfixes3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxfixes3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxi-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxi6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxi6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxinerama-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxinerama1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxinerama1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxkbfile-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxkbfile1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxkbfile1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxkbui-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxkbui1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxkbui1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxmu-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxmu6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxmu6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxmuu-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxmuu1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxmuu1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxp6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxp6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxpm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxpm4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxpm4-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxrandr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxrandr2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxrandr2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxres-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxres1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxres1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxss-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxss1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxss1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxt6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxt6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxtrap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxtrap6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxtrap6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxtst-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxtst6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxtst6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxv-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxv1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxv1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxvmc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxvmc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxvmc1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxxf86dga-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxxf86dga1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxxf86dga1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxxf86misc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxxf86misc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxxf86misc1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxxf86rush-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxxf86rush1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxxf86rush1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxxf86vm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxxf86vm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libxxf86vm1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:pm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:proxymngr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:twm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:x-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:x-window-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:x-window-system-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:x-window-system-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xbase-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfonts-100dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfonts-100dpi-transcoded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfonts-75dpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfonts-75dpi-transcoded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfonts-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfonts-base-transcoded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfonts-cyrillic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfonts-scalable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfree86-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xfwp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa-dri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa-dri-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa-gl-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa-gl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa-glu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa-glu-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa-glu-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibmesa3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibosmesa-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibosmesa4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibosmesa4-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibs-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibs-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibs-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibs-static-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xlibs-static-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xmh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xorg-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xprt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-apm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-ark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-ati");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-chips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-cirrus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-cyrix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-dummy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-fbdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-glide");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-glint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-i128");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-i740");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-i810");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-imstt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-mga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-neomagic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-newport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-nsc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-nv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-rendition");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-s3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-s3virge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-savage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-siliconmotion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-sis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-tdfx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-tga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-trident");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-tseng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-v4l");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-vesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-vga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-via");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-driver-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-acecad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-aiptek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-calcomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-citron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-digitaledge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-dmc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-dynapro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-elographics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-fpit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-hyperpen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-kbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-magellan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-microtouch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-mouse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-mutouch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-palmax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-penmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-spaceorb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-summa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-tek4957");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-void");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xserver-xorg-input-wacom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xspecs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xterm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:xvfb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.04");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:5.10");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2006-2016 Canonical, Inc. / NASL script (C) 2006-2016 Tenable Network Security, Inc.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! ereg(pattern:"^(5\.04|5\.10)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 5.04 / 5.10", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"5.04", pkgname:"lbxproxy", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libdmx-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libdmx1", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libdmx1-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libdps-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libdps1", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libdps1-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libfs-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libfs6", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libfs6-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libice-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libice6", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libice6-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libsm-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libsm6", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libsm6-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libx11-6", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libx11-6-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libx11-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxau-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxau6", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxau6-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxaw6", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxaw6-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxaw6-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxaw7", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxaw7-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxaw7-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxaw8", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxaw8-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxaw8-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxcomposite-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxcomposite1", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxcomposite1-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxdamage-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxdamage1", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxdamage1-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxdmcp-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxdmcp6", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxdmcp6-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxevie-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxevie1", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxevie1-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxext-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxext6", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxext6-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxfixes-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxfixes3", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxfixes3-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxi-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxi6", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxi6-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxinerama-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxinerama1", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxinerama1-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxkbfile-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxkbfile1", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxkbfile1-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxkbui-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxkbui1", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxkbui1-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxmu-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxmu6", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxmu6-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxmuu-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxmuu1", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxmuu1-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxp-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxp6", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxp6-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxpm-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxpm4", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxpm4-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxrandr-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxrandr2", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxrandr2-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxres-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxres1", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxres1-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxss-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxss1", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxss1-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxt-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxt6", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxt6-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxtrap-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxtrap6", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxtrap6-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxtst-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxtst6", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxtst6-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxv-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxv1", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxv1-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxvmc-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxvmc1", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxvmc1-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxxf86dga-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxxf86dga1", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxxf86dga1-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxxf86misc-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxxf86misc1", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxxf86misc1-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxxf86rush-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxxf86rush1", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxxf86rush1-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxxf86vm-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxxf86vm1", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"libxxf86vm1-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"pm-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"proxymngr", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"twm", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"x-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"x-window-system", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"x-window-system-core", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"x-window-system-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xbase-clients", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xdm", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xdmx", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xfonts-100dpi", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xfonts-100dpi-transcoded", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xfonts-75dpi", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xfonts-75dpi-transcoded", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xfonts-base", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xfonts-base-transcoded", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xfonts-cyrillic", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xfonts-scalable", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xfree86-common", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xfs", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xfwp", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xlibmesa-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xlibmesa-dri", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xlibmesa-dri-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xlibmesa-gl", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xlibmesa-gl-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xlibmesa-gl-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xlibmesa-glu", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xlibmesa-glu-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xlibmesa-glu-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xlibmesa3", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xlibmesa3-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xlibosmesa-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xlibosmesa4", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xlibosmesa4-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xlibs", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xlibs-data", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xlibs-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xlibs-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xlibs-pic", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xlibs-static-dev", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xlibs-static-pic", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xmh", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xnest", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xorg-common", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xprt", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xserver-common", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xserver-xorg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xserver-xorg-dbg", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xspecs", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xterm", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xutils", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.04", pkgname:"xvfb", pkgver:"6.8.2-10.2")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"x-window-system-core", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"x-window-system-dev", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xbase-clients", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xdmx", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xlibs", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xlibs-data", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xlibs-dev", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xlibs-static-dev", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xlibs-static-pic", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xnest", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xorg-common", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-common", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-core", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-dbg", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-apm", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-ark", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-ati", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-chips", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-cirrus", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-cyrix", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-dummy", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-fbdev", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-glide", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-glint", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-i128", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-i740", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-i810", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-imstt", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-mga", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-neomagic", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-newport", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-nsc", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-nv", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-rendition", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-s3", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-s3virge", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-savage", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-siliconmotion", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-sis", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-tdfx", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-tga", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-trident", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-tseng", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-v4l", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-vesa", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-vga", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-via", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-driver-vmware", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-acecad", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-aiptek", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-calcomp", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-citron", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-digitaledge", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-dmc", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-dynapro", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-elographics", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-fpit", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-hyperpen", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-kbd", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-magellan", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-microtouch", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-mouse", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-mutouch", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-palmax", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-penmount", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-spaceorb", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-summa", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-tek4957", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-void", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xserver-xorg-input-wacom", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xutils", pkgver:"6.8.2-77.1")) flag++;
if (ubuntu_check(osver:"5.10", pkgname:"xvfb", pkgver:"6.8.2-77.1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lbxproxy / libdmx-dev / libdmx1 / libdmx1-dbg / libdps-dev / etc");
}
