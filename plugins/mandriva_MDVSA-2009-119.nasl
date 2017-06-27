#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:119. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(48145);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id("CVE-2009-1184", "CVE-2009-1192", "CVE-2009-1265", "CVE-2009-1337");
  script_bugtraq_id(34405, 34654, 34673);
  script_xref(name:"MDVSA", value:"2009:119");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2009:119)");
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

The exit_notify function in kernel/exit.c in the Linux kernel before
2.6.30-rc1 does not restrict exit signals when the CAP_KILL capability
is held, which allows local users to send an arbitrary signal to a
process by running a program that modifies the exit_signal field and
then uses an exec system call to launch a setuid application.
(CVE-2009-1337)

The selinux_ip_postroute_iptables_compat function in
security/selinux/hooks.c in the SELinux subsystem in the Linux kernel
before 2.6.27.22, and 2.6.28.x before 2.6.28.10, when compat_net is
enabled, omits calls to avc_has_perm for the (1) node and (2) port,
which allows local users to bypass intended restrictions on network
traffic. NOTE: this was incorrectly reported as an issue fixed in
2.6.27.21. (CVE-2009-1184)

drivers/char/agp/generic.c in the agp subsystem in the Linux kernel
before 2.6.30-rc3 does not zero out pages that may later be available
to a user-space process, which allows local users to obtain sensitive
information by reading these pages. (CVE-2009-1192)

Integer overflow in rose_sendmsg (sys/net/af_rose.c) in the Linux
kernel 2.6.24.4, and other versions before 2.6.30-rc1, might allow
remote attackers to obtain sensitive information via a large length
value, which causes garbage memory to be sent. (CVE-2009-1265)

To update your kernel, please follow the directions located at :

http://www.mandriva.com/en/security/kernelupdate"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:alsa_raoppcm-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:alsa_raoppcm-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:alsa_raoppcm-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:alsa_raoppcm-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:alsa_raoppcm-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:alsa_raoppcm-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:broadcom-wl-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:em8300-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fcpci-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fcpci-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fcpci-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fcpci-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fcpci-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fcpci-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:fglrx-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hcfpcimodem-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hsfmodem-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hso-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hso-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hso-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hso-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hso-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:hso-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-2.6.29.3-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-2.6.29.3-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-devel-2.6.29.3-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-2.6.29.3-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-devel-2.6.29.3-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-2.6.29.3-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel-2.6.29.3-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-2.6.29.3-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kqemu-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kqemu-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kqemu-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kqemu-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kqemu-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kqemu-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libafs-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lirc-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lzma-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:madwifi-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netfilter-rtsp-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netfilter-rtsp-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netfilter-rtsp-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netfilter-rtsp-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netfilter-rtsp-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:netfilter-rtsp-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nouveau-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nouveau-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nouveau-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nouveau-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nouveau-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nouveau-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia-current-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia173-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nvidia96xx-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:opencbm-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:opencbm-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:opencbm-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:opencbm-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:opencbm-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:opencbm-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rt2870-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rt2870-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rt2870-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rt2870-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rt2870-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:rt2870-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:slmodem-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squashfs-lzma-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:syntek-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:syntek-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:syntek-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:syntek-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:syntek-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:syntek-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tp_smapi-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tp_smapi-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tp_smapi-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tp_smapi-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tp_smapi-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tp_smapi-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vboxadditions-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vhba-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vhba-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vhba-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vhba-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vhba-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vhba-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:virtualbox-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-2.6.29.3-desktop-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-2.6.29.3-desktop586-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-2.6.29.3-server-1mnb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-desktop-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-desktop586-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vpnclient-kernel-server-latest");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.1", reference:"alsa_raoppcm-kernel-2.6.29.3-desktop-1mnb-0.5.1-2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"alsa_raoppcm-kernel-2.6.29.3-desktop586-1mnb-0.5.1-2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"alsa_raoppcm-kernel-2.6.29.3-server-1mnb-0.5.1-2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"alsa_raoppcm-kernel-desktop-latest-0.5.1-1.20090515.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"alsa_raoppcm-kernel-desktop586-latest-0.5.1-1.20090515.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"alsa_raoppcm-kernel-server-latest-0.5.1-1.20090515.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"broadcom-wl-kernel-2.6.29.3-desktop-1mnb-5.10.79.10-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"broadcom-wl-kernel-2.6.29.3-desktop586-1mnb-5.10.79.10-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"broadcom-wl-kernel-2.6.29.3-server-1mnb-5.10.79.10-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"broadcom-wl-kernel-desktop-latest-5.10.79.10-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"broadcom-wl-kernel-desktop586-latest-5.10.79.10-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"broadcom-wl-kernel-server-latest-5.10.79.10-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"em8300-kernel-2.6.29.3-desktop-1mnb-0.17.2-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"em8300-kernel-2.6.29.3-desktop586-1mnb-0.17.2-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"em8300-kernel-2.6.29.3-server-1mnb-0.17.2-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"em8300-kernel-desktop-latest-0.17.2-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"em8300-kernel-desktop586-latest-0.17.2-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"em8300-kernel-server-latest-0.17.2-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"fcpci-kernel-2.6.29.3-desktop-1mnb-3.11.07-7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"fcpci-kernel-2.6.29.3-desktop586-1mnb-3.11.07-7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"fcpci-kernel-2.6.29.3-server-1mnb-3.11.07-7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"fcpci-kernel-desktop-latest-3.11.07-1.20090515.7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"fcpci-kernel-desktop586-latest-3.11.07-1.20090515.7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"fcpci-kernel-server-latest-3.11.07-1.20090515.7mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"fglrx-kernel-2.6.29.3-desktop-1mnb-8.600-2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"fglrx-kernel-2.6.29.3-desktop586-1mnb-8.600-2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"fglrx-kernel-2.6.29.3-server-1mnb-8.600-2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"fglrx-kernel-desktop-latest-8.600-1.20090515.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"fglrx-kernel-desktop586-latest-8.600-1.20090515.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"fglrx-kernel-server-latest-8.600-1.20090515.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"hcfpcimodem-kernel-2.6.29.3-desktop-1mnb-1.18-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"hcfpcimodem-kernel-2.6.29.3-desktop586-1mnb-1.18-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"hcfpcimodem-kernel-2.6.29.3-server-1mnb-1.18-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"hcfpcimodem-kernel-desktop-latest-1.18-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"hcfpcimodem-kernel-desktop586-latest-1.18-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"hcfpcimodem-kernel-server-latest-1.18-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"hsfmodem-kernel-2.6.29.3-desktop-1mnb-7.80.02.03-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"hsfmodem-kernel-2.6.29.3-desktop586-1mnb-7.80.02.03-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"hsfmodem-kernel-2.6.29.3-server-1mnb-7.80.02.03-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"hsfmodem-kernel-desktop-latest-7.80.02.03-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"hsfmodem-kernel-desktop586-latest-7.80.02.03-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"hsfmodem-kernel-server-latest-7.80.02.03-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"hso-kernel-2.6.29.3-desktop-1mnb-1.2-3mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"hso-kernel-2.6.29.3-desktop586-1mnb-1.2-3mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"hso-kernel-2.6.29.3-server-1mnb-1.2-3mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"hso-kernel-desktop-latest-1.2-1.20090515.3mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"hso-kernel-desktop586-latest-1.2-1.20090515.3mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"hso-kernel-server-latest-1.2-1.20090515.3mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-2.6.29.3-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-desktop-2.6.29.3-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-desktop-devel-2.6.29.3-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-desktop-devel-latest-2.6.29.3-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-desktop-latest-2.6.29.3-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"kernel-desktop586-2.6.29.3-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"kernel-desktop586-devel-2.6.29.3-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"kernel-desktop586-devel-latest-2.6.29.3-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"kernel-desktop586-latest-2.6.29.3-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-doc-2.6.29.3-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-server-2.6.29.3-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-server-devel-2.6.29.3-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-server-devel-latest-2.6.29.3-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-server-latest-2.6.29.3-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-source-2.6.29.3-1mnb-1-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kernel-source-latest-2.6.29.3-1mnb2")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kqemu-kernel-2.6.29.3-desktop-1mnb-1.4.0pre1-4")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"kqemu-kernel-2.6.29.3-desktop586-1mnb-1.4.0pre1-4")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kqemu-kernel-2.6.29.3-server-1mnb-1.4.0pre1-4")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kqemu-kernel-desktop-latest-1.4.0pre1-1.20090515.4")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"kqemu-kernel-desktop586-latest-1.4.0pre1-1.20090515.4")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kqemu-kernel-server-latest-1.4.0pre1-1.20090515.4")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"libafs-kernel-2.6.29.3-desktop-1mnb-1.4.10-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libafs-kernel-2.6.29.3-desktop586-1mnb-1.4.10-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"libafs-kernel-2.6.29.3-server-1mnb-1.4.10-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"libafs-kernel-desktop-latest-1.4.10-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libafs-kernel-desktop586-latest-1.4.10-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"libafs-kernel-server-latest-1.4.10-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"lirc-kernel-2.6.29.3-desktop-1mnb-0.8.5-0.20090320.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"lirc-kernel-2.6.29.3-desktop586-1mnb-0.8.5-0.20090320.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"lirc-kernel-2.6.29.3-server-1mnb-0.8.5-0.20090320.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"lirc-kernel-desktop-latest-0.8.5-1.20090515.0.20090320.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"lirc-kernel-desktop586-latest-0.8.5-1.20090515.0.20090320.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"lirc-kernel-server-latest-0.8.5-1.20090515.0.20090320.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"lzma-kernel-2.6.29.3-desktop-1mnb-4.43-27mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"lzma-kernel-2.6.29.3-desktop586-1mnb-4.43-27mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"lzma-kernel-2.6.29.3-server-1mnb-4.43-27mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"lzma-kernel-desktop-latest-4.43-1.20090515.27mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"lzma-kernel-desktop586-latest-4.43-1.20090515.27mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"lzma-kernel-server-latest-4.43-1.20090515.27mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"madwifi-kernel-2.6.29.3-desktop-1mnb-0.9.4-4.r3998mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"madwifi-kernel-2.6.29.3-desktop586-1mnb-0.9.4-4.r3998mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"madwifi-kernel-2.6.29.3-server-1mnb-0.9.4-4.r3998mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"madwifi-kernel-desktop-latest-0.9.4-1.20090515.4.r3998mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"madwifi-kernel-desktop586-latest-0.9.4-1.20090515.4.r3998mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"madwifi-kernel-server-latest-0.9.4-1.20090515.4.r3998mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"netfilter-rtsp-kernel-2.6.29.3-desktop-1mnb-2.6.26-2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"netfilter-rtsp-kernel-2.6.29.3-desktop586-1mnb-2.6.26-2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"netfilter-rtsp-kernel-2.6.29.3-server-1mnb-2.6.26-2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"netfilter-rtsp-kernel-desktop-latest-2.6.26-1.20090515.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"netfilter-rtsp-kernel-desktop586-latest-2.6.26-1.20090515.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"netfilter-rtsp-kernel-server-latest-2.6.26-1.20090515.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nouveau-kernel-2.6.29.3-desktop-1mnb-0.0.12-0.20090329.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"nouveau-kernel-2.6.29.3-desktop586-1mnb-0.0.12-0.20090329.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nouveau-kernel-2.6.29.3-server-1mnb-0.0.12-0.20090329.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nouveau-kernel-desktop-latest-0.0.12-1.20090515.0.20090329.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"nouveau-kernel-desktop586-latest-0.0.12-1.20090515.0.20090329.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nouveau-kernel-server-latest-0.0.12-1.20090515.0.20090329.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia-current-kernel-2.6.29.3-desktop-1mnb-180.51-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"nvidia-current-kernel-2.6.29.3-desktop586-1mnb-180.51-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia-current-kernel-2.6.29.3-server-1mnb-180.51-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia-current-kernel-desktop-latest-180.51-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"nvidia-current-kernel-desktop586-latest-180.51-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia-current-kernel-server-latest-180.51-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia173-kernel-2.6.29.3-desktop-1mnb-173.14.18-2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"nvidia173-kernel-2.6.29.3-desktop586-1mnb-173.14.18-2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia173-kernel-2.6.29.3-server-1mnb-173.14.18-2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia173-kernel-desktop-latest-173.14.18-1.20090515.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"nvidia173-kernel-desktop586-latest-173.14.18-1.20090515.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia173-kernel-server-latest-173.14.18-1.20090515.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia96xx-kernel-2.6.29.3-desktop-1mnb-96.43.11-5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"nvidia96xx-kernel-2.6.29.3-desktop586-1mnb-96.43.11-5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia96xx-kernel-2.6.29.3-server-1mnb-96.43.11-5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia96xx-kernel-desktop-latest-96.43.11-1.20090515.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"nvidia96xx-kernel-desktop586-latest-96.43.11-1.20090515.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"nvidia96xx-kernel-server-latest-96.43.11-1.20090515.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"opencbm-kernel-2.6.29.3-desktop-1mnb-0.4.2a-4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"opencbm-kernel-2.6.29.3-desktop586-1mnb-0.4.2a-4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"opencbm-kernel-2.6.29.3-server-1mnb-0.4.2a-4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"opencbm-kernel-desktop-latest-0.4.2a-1.20090515.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"opencbm-kernel-desktop586-latest-0.4.2a-1.20090515.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"opencbm-kernel-server-latest-0.4.2a-1.20090515.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"rt2870-kernel-2.6.29.3-desktop-1mnb-1.4.0.0-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"rt2870-kernel-2.6.29.3-desktop586-1mnb-1.4.0.0-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"rt2870-kernel-2.6.29.3-server-1mnb-1.4.0.0-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"rt2870-kernel-desktop-latest-1.4.0.0-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"rt2870-kernel-desktop586-latest-1.4.0.0-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"rt2870-kernel-server-latest-1.4.0.0-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"slmodem-kernel-2.6.29.3-desktop-1mnb-2.9.11-0.20080817.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"slmodem-kernel-2.6.29.3-desktop586-1mnb-2.9.11-0.20080817.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"slmodem-kernel-2.6.29.3-server-1mnb-2.9.11-0.20080817.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"slmodem-kernel-desktop-latest-2.9.11-1.20090515.0.20080817.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"slmodem-kernel-desktop586-latest-2.9.11-1.20090515.0.20080817.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"slmodem-kernel-server-latest-2.9.11-1.20090515.0.20080817.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"squashfs-kernel-2.6.29.3-desktop-1mnb-3.4-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"squashfs-kernel-2.6.29.3-desktop586-1mnb-3.4-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"squashfs-kernel-2.6.29.3-server-1mnb-3.4-1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"squashfs-kernel-desktop-latest-3.4-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"squashfs-kernel-desktop586-latest-3.4-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"squashfs-kernel-server-latest-3.4-1.20090515.1mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"squashfs-lzma-kernel-2.6.29.3-desktop-1mnb-3.3-10mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"squashfs-lzma-kernel-2.6.29.3-desktop586-1mnb-3.3-10mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"squashfs-lzma-kernel-2.6.29.3-server-1mnb-3.3-10mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"squashfs-lzma-kernel-desktop-latest-3.3-1.20090515.10mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"squashfs-lzma-kernel-desktop586-latest-3.3-1.20090515.10mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"squashfs-lzma-kernel-server-latest-3.3-1.20090515.10mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"syntek-kernel-2.6.29.3-desktop-1mnb-1.3.1-5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"syntek-kernel-2.6.29.3-desktop586-1mnb-1.3.1-5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"syntek-kernel-2.6.29.3-server-1mnb-1.3.1-5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"syntek-kernel-desktop-latest-1.3.1-1.20090515.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"syntek-kernel-desktop586-latest-1.3.1-1.20090515.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"syntek-kernel-server-latest-1.3.1-1.20090515.5mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tp_smapi-kernel-2.6.29.3-desktop-1mnb-0.40-2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"tp_smapi-kernel-2.6.29.3-desktop586-1mnb-0.40-2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tp_smapi-kernel-2.6.29.3-server-1mnb-0.40-2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tp_smapi-kernel-desktop-latest-0.40-1.20090515.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"tp_smapi-kernel-desktop586-latest-0.40-1.20090515.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"tp_smapi-kernel-server-latest-0.40-1.20090515.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"vboxadditions-kernel-2.6.29.3-desktop-1mnb-2.2.0-4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"vboxadditions-kernel-2.6.29.3-desktop586-1mnb-2.2.0-4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"vboxadditions-kernel-2.6.29.3-server-1mnb-2.2.0-4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"vboxadditions-kernel-desktop-latest-2.2.0-1.20090515.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"vboxadditions-kernel-desktop586-latest-2.2.0-1.20090515.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"vboxadditions-kernel-server-latest-2.2.0-1.20090515.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"vhba-kernel-2.6.29.3-desktop-1mnb-1.2.1-2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"vhba-kernel-2.6.29.3-desktop586-1mnb-1.2.1-2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"vhba-kernel-2.6.29.3-server-1mnb-1.2.1-2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"vhba-kernel-desktop-latest-1.2.1-1.20090519.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"vhba-kernel-desktop586-latest-1.2.1-1.20090519.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"vhba-kernel-server-latest-1.2.1-1.20090519.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"virtualbox-kernel-2.6.29.3-desktop-1mnb-2.2.0-4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"virtualbox-kernel-2.6.29.3-desktop586-1mnb-2.2.0-4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"virtualbox-kernel-2.6.29.3-server-1mnb-2.2.0-4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"virtualbox-kernel-desktop-latest-2.2.0-1.20090515.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"virtualbox-kernel-desktop586-latest-2.2.0-1.20090515.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"virtualbox-kernel-server-latest-2.2.0-1.20090515.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"vpnclient-kernel-2.6.29.3-desktop-1mnb-4.8.01.0640-3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"vpnclient-kernel-2.6.29.3-desktop586-1mnb-4.8.01.0640-3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"vpnclient-kernel-2.6.29.3-server-1mnb-4.8.01.0640-3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"vpnclient-kernel-desktop-latest-4.8.01.0640-1.20090515.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"vpnclient-kernel-desktop586-latest-4.8.01.0640-1.20090515.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"vpnclient-kernel-server-latest-4.8.01.0640-1.20090515.3mdv2009.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
