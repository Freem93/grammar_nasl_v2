#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:234. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(38027);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/28 21:39:22 $");

  script_cve_id("CVE-2008-4933", "CVE-2008-4934", "CVE-2008-5029");
  script_xref(name:"MDVSA", value:"2008:234");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2008:234)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Some vulnerabilities were discovered and corrected in the Linux 2.6
kernel :

Buffer overflow in the hfsplus_find_cat function in
fs/hfsplus/catalog.c in the Linux kernel before 2.6.28-rc1 allows
attackers to cause a denial of service (memory corruption or system
crash) via an hfsplus filesystem image with an invalid catalog
namelength field, related to the hfsplus_cat_build_key_uni function.
(CVE-2008-4933)

The hfsplus_block_allocate function in fs/hfsplus/bitmap.c in the
Linux kernel before 2.6.28-rc1 does not check a certain return value
from the read_mapping_page function before calling kmap, which allows
attackers to cause a denial of service (system crash) via a crafted
hfsplus filesystem image. (CVE-2008-4934)

The __scm_destroy function in net/core/scm.c in the Linux kernel
2.6.27.4, 2.6.26, and earlier makes indirect recursive calls to itself
through calls to the fput function, which allows local users to cause
a denial of service (panic) via vectors related to sending an
SCM_RIGHTS message through a UNIX domain socket and closing file
descriptors. (CVE-2008-5029)

Additionaly, support for a broadcom bluetooth dongle was added to
btusb driver, an eeepc shutdown hang caused by snd-hda-intel was
fixed, a Realtek auto-mute bug was fixed, the pcspkr driver was
reenabled, an acpi brightness setting issue on some laptops was fixed,
sata_nv (NVidia) driver bugs were fixed, horizontal mousewheel
scrolling with Logitech V150 mouse was fixed, and more. Check the
changelog and related bugs for more details.

This kernel also fixes the driver for Intel G45/GM45 video chipsets,
in a way requiring also an updated Xorg driver, which is also being
provided in this update.

To update your kernel, please follow the directions located at :

http://www.mandriva.com/en/security/kernelupdate"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://qa.mandriva.com/44309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://qa.mandriva.com/44612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://qa.mandriva.com/44712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://qa.mandriva.com/44752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://qa.mandriva.com/44870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://qa.mandriva.com/44886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://qa.mandriva.com/45319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://qa.mandriva.com/45618"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:alsa_raoppcm-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:alsa_raoppcm-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:alsa_raoppcm-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:alsa_raoppcm-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:alsa_raoppcm-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:alsa_raoppcm-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drm-experimental-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drm-experimental-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drm-experimental-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drm-experimental-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drm-experimental-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drm-experimental-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:et131x-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:et131x-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:et131x-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:et131x-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:et131x-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:et131x-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fcpci-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fcpci-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fcpci-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fcpci-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fcpci-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fcpci-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnbd-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnbd-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnbd-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnbd-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnbd-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnbd-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hso-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hso-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hso-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hso-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hso-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hso-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:iscsitarget-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:iscsitarget-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:iscsitarget-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:iscsitarget-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:iscsitarget-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:iscsitarget-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.27.5-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-2.6.27.5-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-devel-2.6.27.5-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-2.6.27.5-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-devel-2.6.27.5-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-2.6.27.5-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel-2.6.27.5-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.6.27.5-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kqemu-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kqemu-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kqemu-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kqemu-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kqemu-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kqemu-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia71xx-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia71xx-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia71xx-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia71xx-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia71xx-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia71xx-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:omfs-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:omfs-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:omfs-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:omfs-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:omfs-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:omfs-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:omnibook-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:omnibook-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:omnibook-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:omnibook-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:omnibook-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:omnibook-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:opencbm-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:opencbm-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:opencbm-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:opencbm-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:opencbm-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:opencbm-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ov51x-jpeg-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ov51x-jpeg-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ov51x-jpeg-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ov51x-jpeg-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ov51x-jpeg-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ov51x-jpeg-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qc-usb-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qc-usb-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qc-usb-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qc-usb-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qc-usb-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:qc-usb-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rt2860-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rt2860-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rt2860-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rt2860-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rt2860-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rt2860-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rt2870-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rt2870-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rt2870-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rt2870-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rt2870-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rt2870-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rtl8187se-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rtl8187se-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rtl8187se-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rtl8187se-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rtl8187se-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rtl8187se-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tp_smapi-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tp_smapi-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tp_smapi-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tp_smapi-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tp_smapi-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tp_smapi-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadd-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadd-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadd-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadd-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadd-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadd-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxvfs-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxvfs-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxvfs-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxvfs-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxvfs-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxvfs-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vhba-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vhba-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vhba-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vhba-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vhba-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vhba-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-2.6.27.5-desktop-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-2.6.27.5-desktop586-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-2.6.27.5-server-2mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-driver-video-intel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-driver-video-intel-fast-i830");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK2009.0", reference:"alsa_raoppcm-kernel-2.6.27.5-desktop-2mnb-0.5.1-2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"alsa_raoppcm-kernel-2.6.27.5-desktop586-2mnb-0.5.1-2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"alsa_raoppcm-kernel-2.6.27.5-server-2mnb-0.5.1-2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"alsa_raoppcm-kernel-desktop-latest-0.5.1-1.20081121.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"alsa_raoppcm-kernel-desktop586-latest-0.5.1-1.20081121.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"alsa_raoppcm-kernel-server-latest-0.5.1-1.20081121.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"drm-experimental-kernel-2.6.27.5-desktop-2mnb-2.3.0-2.20080912.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"drm-experimental-kernel-2.6.27.5-desktop586-2mnb-2.3.0-2.20080912.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"drm-experimental-kernel-2.6.27.5-server-2mnb-2.3.0-2.20080912.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"drm-experimental-kernel-desktop-latest-2.3.0-1.20081121.2.20080912.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"drm-experimental-kernel-desktop586-latest-2.3.0-1.20081121.2.20080912.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"drm-experimental-kernel-server-latest-2.3.0-1.20081121.2.20080912.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"et131x-kernel-2.6.27.5-desktop-2mnb-1.2.3-7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"et131x-kernel-2.6.27.5-desktop586-2mnb-1.2.3-7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"et131x-kernel-2.6.27.5-server-2mnb-1.2.3-7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"et131x-kernel-desktop-latest-1.2.3-1.20081121.7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"et131x-kernel-desktop586-latest-1.2.3-1.20081121.7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"et131x-kernel-server-latest-1.2.3-1.20081121.7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"fcpci-kernel-2.6.27.5-desktop-2mnb-3.11.07-7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"fcpci-kernel-2.6.27.5-desktop586-2mnb-3.11.07-7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"fcpci-kernel-2.6.27.5-server-2mnb-3.11.07-7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"fcpci-kernel-desktop-latest-3.11.07-1.20081121.7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"fcpci-kernel-desktop586-latest-3.11.07-1.20081121.7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"fcpci-kernel-server-latest-3.11.07-1.20081121.7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"fglrx-kernel-2.6.27.5-desktop-2mnb-8.522-3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"fglrx-kernel-2.6.27.5-desktop586-2mnb-8.522-3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"fglrx-kernel-2.6.27.5-server-2mnb-8.522-3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"fglrx-kernel-desktop-latest-8.522-1.20081121.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"fglrx-kernel-desktop586-latest-8.522-1.20081121.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"fglrx-kernel-server-latest-8.522-1.20081121.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gnbd-kernel-2.6.27.5-desktop-2mnb-2.03.07-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"gnbd-kernel-2.6.27.5-desktop586-2mnb-2.03.07-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gnbd-kernel-2.6.27.5-server-2mnb-2.03.07-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gnbd-kernel-desktop-latest-2.03.07-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"gnbd-kernel-desktop586-latest-2.03.07-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"gnbd-kernel-server-latest-2.03.07-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"hcfpcimodem-kernel-2.6.27.5-desktop-2mnb-1.17-1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"hcfpcimodem-kernel-2.6.27.5-desktop586-2mnb-1.17-1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"hcfpcimodem-kernel-2.6.27.5-server-2mnb-1.17-1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"hcfpcimodem-kernel-desktop-latest-1.17-1.20081121.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"hcfpcimodem-kernel-desktop586-latest-1.17-1.20081121.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"hcfpcimodem-kernel-server-latest-1.17-1.20081121.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"hsfmodem-kernel-2.6.27.5-desktop-2mnb-7.68.00.13-1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"hsfmodem-kernel-2.6.27.5-desktop586-2mnb-7.68.00.13-1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"hsfmodem-kernel-2.6.27.5-server-2mnb-7.68.00.13-1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"hsfmodem-kernel-desktop-latest-7.68.00.13-1.20081121.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"hsfmodem-kernel-desktop586-latest-7.68.00.13-1.20081121.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"hsfmodem-kernel-server-latest-7.68.00.13-1.20081121.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"hso-kernel-2.6.27.5-desktop-2mnb-1.2-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"hso-kernel-2.6.27.5-desktop586-2mnb-1.2-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"hso-kernel-2.6.27.5-server-2mnb-1.2-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"hso-kernel-desktop-latest-1.2-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"hso-kernel-desktop586-latest-1.2-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"hso-kernel-server-latest-1.2-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"iscsitarget-kernel-2.6.27.5-desktop-2mnb-0.4.16-4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"iscsitarget-kernel-2.6.27.5-desktop586-2mnb-0.4.16-4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"iscsitarget-kernel-2.6.27.5-server-2mnb-0.4.16-4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"iscsitarget-kernel-desktop-latest-0.4.16-1.20081121.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"iscsitarget-kernel-desktop586-latest-0.4.16-1.20081121.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"iscsitarget-kernel-server-latest-0.4.16-1.20081121.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kernel-2.6.27.5-2mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kernel-desktop-2.6.27.5-2mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kernel-desktop-devel-2.6.27.5-2mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kernel-desktop-devel-latest-2.6.27.5-2mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kernel-desktop-latest-2.6.27.5-2mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"kernel-desktop586-2.6.27.5-2mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"kernel-desktop586-devel-2.6.27.5-2mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"kernel-desktop586-devel-latest-2.6.27.5-2mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"kernel-desktop586-latest-2.6.27.5-2mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kernel-doc-2.6.27.5-2mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kernel-server-2.6.27.5-2mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kernel-server-devel-2.6.27.5-2mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kernel-server-devel-latest-2.6.27.5-2mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kernel-server-latest-2.6.27.5-2mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kernel-source-2.6.27.5-2mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kernel-source-latest-2.6.27.5-2mnb2")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kqemu-kernel-2.6.27.5-desktop-2mnb-1.4.0pre1-0")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"kqemu-kernel-2.6.27.5-desktop586-2mnb-1.4.0pre1-0")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kqemu-kernel-2.6.27.5-server-2mnb-1.4.0pre1-0")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kqemu-kernel-desktop-latest-1.4.0pre1-1.20081121.0")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"kqemu-kernel-desktop586-latest-1.4.0pre1-1.20081121.0")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kqemu-kernel-server-latest-1.4.0pre1-1.20081121.0")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"lirc-kernel-2.6.27.5-desktop-2mnb-0.8.3-4.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"lirc-kernel-2.6.27.5-desktop586-2mnb-0.8.3-4.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"lirc-kernel-2.6.27.5-server-2mnb-0.8.3-4.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"lirc-kernel-desktop-latest-0.8.3-1.20081121.4.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"lirc-kernel-desktop586-latest-0.8.3-1.20081121.4.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"lirc-kernel-server-latest-0.8.3-1.20081121.4.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"lzma-kernel-2.6.27.5-desktop-2mnb-4.43-24mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"lzma-kernel-2.6.27.5-desktop586-2mnb-4.43-24mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"lzma-kernel-2.6.27.5-server-2mnb-4.43-24mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"lzma-kernel-desktop-latest-4.43-1.20081121.24mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"lzma-kernel-desktop586-latest-4.43-1.20081121.24mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"lzma-kernel-server-latest-4.43-1.20081121.24mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"madwifi-kernel-2.6.27.5-desktop-2mnb-0.9.4-3.r3835mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"madwifi-kernel-2.6.27.5-desktop586-2mnb-0.9.4-3.r3835mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"madwifi-kernel-2.6.27.5-server-2mnb-0.9.4-3.r3835mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"madwifi-kernel-desktop-latest-0.9.4-1.20081121.3.r3835mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"madwifi-kernel-desktop586-latest-0.9.4-1.20081121.3.r3835mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"madwifi-kernel-server-latest-0.9.4-1.20081121.3.r3835mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"nvidia-current-kernel-2.6.27.5-desktop-2mnb-177.70-2.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"nvidia-current-kernel-2.6.27.5-desktop586-2mnb-177.70-2.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"nvidia-current-kernel-2.6.27.5-server-2mnb-177.70-2.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"nvidia-current-kernel-desktop-latest-177.70-1.20081121.2.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"nvidia-current-kernel-desktop586-latest-177.70-1.20081121.2.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"nvidia-current-kernel-server-latest-177.70-1.20081121.2.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"nvidia173-kernel-2.6.27.5-desktop-2mnb-173.14.12-4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"nvidia173-kernel-2.6.27.5-desktop586-2mnb-173.14.12-4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"nvidia173-kernel-2.6.27.5-server-2mnb-173.14.12-4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"nvidia173-kernel-desktop-latest-173.14.12-1.20081121.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"nvidia173-kernel-desktop586-latest-173.14.12-1.20081121.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"nvidia173-kernel-server-latest-173.14.12-1.20081121.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"nvidia71xx-kernel-2.6.27.5-desktop-2mnb-71.86.06-5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"nvidia71xx-kernel-2.6.27.5-desktop586-2mnb-71.86.06-5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"nvidia71xx-kernel-2.6.27.5-server-2mnb-71.86.06-5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"nvidia71xx-kernel-desktop-latest-71.86.06-1.20081121.5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"nvidia71xx-kernel-desktop586-latest-71.86.06-1.20081121.5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"nvidia71xx-kernel-server-latest-71.86.06-1.20081121.5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"nvidia96xx-kernel-2.6.27.5-desktop-2mnb-96.43.07-5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"nvidia96xx-kernel-2.6.27.5-desktop586-2mnb-96.43.07-5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"nvidia96xx-kernel-2.6.27.5-server-2mnb-96.43.07-5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"nvidia96xx-kernel-desktop-latest-96.43.07-1.20081121.5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"nvidia96xx-kernel-desktop586-latest-96.43.07-1.20081121.5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"nvidia96xx-kernel-server-latest-96.43.07-1.20081121.5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"omfs-kernel-2.6.27.5-desktop-2mnb-0.8.0-1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"omfs-kernel-2.6.27.5-desktop586-2mnb-0.8.0-1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"omfs-kernel-2.6.27.5-server-2mnb-0.8.0-1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"omfs-kernel-desktop-latest-0.8.0-1.20081121.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"omfs-kernel-desktop586-latest-0.8.0-1.20081121.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"omfs-kernel-server-latest-0.8.0-1.20081121.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"omnibook-kernel-2.6.27.5-desktop-2mnb-20080513-0.274.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"omnibook-kernel-2.6.27.5-desktop586-2mnb-20080513-0.274.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"omnibook-kernel-2.6.27.5-server-2mnb-20080513-0.274.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"omnibook-kernel-desktop-latest-20080513-1.20081121.0.274.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"omnibook-kernel-desktop586-latest-20080513-1.20081121.0.274.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"omnibook-kernel-server-latest-20080513-1.20081121.0.274.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"opencbm-kernel-2.6.27.5-desktop-2mnb-0.4.2a-1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"opencbm-kernel-2.6.27.5-desktop586-2mnb-0.4.2a-1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"opencbm-kernel-2.6.27.5-server-2mnb-0.4.2a-1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"opencbm-kernel-desktop-latest-0.4.2a-1.20081121.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"opencbm-kernel-desktop586-latest-0.4.2a-1.20081121.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"opencbm-kernel-server-latest-0.4.2a-1.20081121.1mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"ov51x-jpeg-kernel-2.6.27.5-desktop-2mnb-1.5.8-1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"ov51x-jpeg-kernel-2.6.27.5-desktop586-2mnb-1.5.8-1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"ov51x-jpeg-kernel-2.6.27.5-server-2mnb-1.5.8-1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"ov51x-jpeg-kernel-desktop-latest-1.5.8-1.20081121.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"ov51x-jpeg-kernel-desktop586-latest-1.5.8-1.20081121.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"ov51x-jpeg-kernel-server-latest-1.5.8-1.20081121.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qc-usb-kernel-2.6.27.5-desktop-2mnb-0.6.6-6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"qc-usb-kernel-2.6.27.5-desktop586-2mnb-0.6.6-6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qc-usb-kernel-2.6.27.5-server-2mnb-0.6.6-6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qc-usb-kernel-desktop-latest-0.6.6-1.20081121.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"qc-usb-kernel-desktop586-latest-0.6.6-1.20081121.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"qc-usb-kernel-server-latest-0.6.6-1.20081121.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"rt2860-kernel-2.6.27.5-desktop-2mnb-1.7.0.0-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"rt2860-kernel-2.6.27.5-desktop586-2mnb-1.7.0.0-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"rt2860-kernel-2.6.27.5-server-2mnb-1.7.0.0-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"rt2860-kernel-desktop-latest-1.7.0.0-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"rt2860-kernel-desktop586-latest-1.7.0.0-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"rt2860-kernel-server-latest-1.7.0.0-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"rt2870-kernel-2.6.27.5-desktop-2mnb-1.3.1.0-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"rt2870-kernel-2.6.27.5-desktop586-2mnb-1.3.1.0-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"rt2870-kernel-2.6.27.5-server-2mnb-1.3.1.0-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"rt2870-kernel-desktop-latest-1.3.1.0-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"rt2870-kernel-desktop586-latest-1.3.1.0-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"rt2870-kernel-server-latest-1.3.1.0-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"rtl8187se-kernel-2.6.27.5-desktop-2mnb-1016.20080716-1.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"rtl8187se-kernel-2.6.27.5-desktop586-2mnb-1016.20080716-1.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"rtl8187se-kernel-2.6.27.5-server-2mnb-1016.20080716-1.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"rtl8187se-kernel-desktop-latest-1016.20080716-1.20081121.1.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"rtl8187se-kernel-desktop586-latest-1016.20080716-1.20081121.1.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"rtl8187se-kernel-server-latest-1016.20080716-1.20081121.1.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"slmodem-kernel-2.6.27.5-desktop-2mnb-2.9.11-0.20080817.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"slmodem-kernel-2.6.27.5-desktop586-2mnb-2.9.11-0.20080817.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"slmodem-kernel-2.6.27.5-server-2mnb-2.9.11-0.20080817.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"slmodem-kernel-desktop-latest-2.9.11-1.20081121.0.20080817.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"slmodem-kernel-desktop586-latest-2.9.11-1.20081121.0.20080817.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"slmodem-kernel-server-latest-2.9.11-1.20081121.0.20080817.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"squashfs-lzma-kernel-2.6.27.5-desktop-2mnb-3.3-5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"squashfs-lzma-kernel-2.6.27.5-desktop586-2mnb-3.3-5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"squashfs-lzma-kernel-2.6.27.5-server-2mnb-3.3-5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"squashfs-lzma-kernel-desktop-latest-3.3-1.20081121.5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"squashfs-lzma-kernel-desktop586-latest-3.3-1.20081121.5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"squashfs-lzma-kernel-server-latest-3.3-1.20081121.5mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tp_smapi-kernel-2.6.27.5-desktop-2mnb-0.37-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"tp_smapi-kernel-2.6.27.5-desktop586-2mnb-0.37-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tp_smapi-kernel-2.6.27.5-server-2mnb-0.37-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tp_smapi-kernel-desktop-latest-0.37-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"tp_smapi-kernel-desktop586-latest-0.37-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"tp_smapi-kernel-server-latest-0.37-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vboxadd-kernel-2.6.27.5-desktop-2mnb-2.0.2-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"vboxadd-kernel-2.6.27.5-desktop586-2mnb-2.0.2-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vboxadd-kernel-2.6.27.5-server-2mnb-2.0.2-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vboxadd-kernel-desktop-latest-2.0.2-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"vboxadd-kernel-desktop586-latest-2.0.2-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vboxadd-kernel-server-latest-2.0.2-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vboxvfs-kernel-2.6.27.5-desktop-2mnb-2.0.2-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"vboxvfs-kernel-2.6.27.5-desktop586-2mnb-2.0.2-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vboxvfs-kernel-2.6.27.5-server-2mnb-2.0.2-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vboxvfs-kernel-desktop-latest-2.0.2-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"vboxvfs-kernel-desktop586-latest-2.0.2-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vboxvfs-kernel-server-latest-2.0.2-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vhba-kernel-2.6.27.5-desktop-2mnb-1.0.0-1.svn304.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"vhba-kernel-2.6.27.5-desktop586-2mnb-1.0.0-1.svn304.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vhba-kernel-2.6.27.5-server-2mnb-1.0.0-1.svn304.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vhba-kernel-desktop-latest-1.0.0-1.20081121.1.svn304.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"vhba-kernel-desktop586-latest-1.0.0-1.20081121.1.svn304.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vhba-kernel-server-latest-1.0.0-1.20081121.1.svn304.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"virtualbox-kernel-2.6.27.5-desktop-2mnb-2.0.2-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"virtualbox-kernel-2.6.27.5-desktop586-2mnb-2.0.2-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"virtualbox-kernel-2.6.27.5-server-2mnb-2.0.2-2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"virtualbox-kernel-desktop-latest-2.0.2-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"virtualbox-kernel-desktop586-latest-2.0.2-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"virtualbox-kernel-server-latest-2.0.2-1.20081121.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vpnclient-kernel-2.6.27.5-desktop-2mnb-4.8.01.0640-3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"vpnclient-kernel-2.6.27.5-desktop586-2mnb-4.8.01.0640-3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vpnclient-kernel-2.6.27.5-server-2mnb-4.8.01.0640-3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vpnclient-kernel-desktop-latest-4.8.01.0640-1.20081121.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"vpnclient-kernel-desktop586-latest-4.8.01.0640-1.20081121.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vpnclient-kernel-server-latest-4.8.01.0640-1.20081121.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"x11-driver-video-intel-2.4.2-7.4mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"x11-driver-video-intel-fast-i830-2.4.2-7.4mdv2009.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
