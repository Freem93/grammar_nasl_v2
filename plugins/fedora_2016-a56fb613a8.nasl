#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-a56fb613a8.
#

include("compat.inc");

if (description)
{
  script_id(94122);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/10/19 14:37:27 $");

  script_cve_id("CVE-2016-6351", "CVE-2016-6490", "CVE-2016-6833", "CVE-2016-7156", "CVE-2016-7161", "CVE-2016-7170", "CVE-2016-7422", "CVE-2016-7466", "CVE-2016-7908", "CVE-2016-7995", "CVE-2016-8576");
  script_xref(name:"FEDORA", value:"2016-a56fb613a8");

  script_name(english:"Fedora 24 : 2:qemu (2016-a56fb613a8)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - CVE-2016-6351: scsi: esp: OOB write access in esp_do_dma
    (bz #1360600)

  - CVE-2016-6833: vmxnet3: use-after-free (bz #1368982)

  - CVE-2016-6490: virtio: infinite loop in virtqueue_pop
    (bz #1361428)

  - CVE-2016-7156: pvscsi: infinite loop when building SG
    list (bz #1373480)

  - CVE-2016-7170: vmware_vga: OOB stack memory access (bz
    #1374709)

  - CVE-2016-7161: net: Heap overflow in
    xlnx.xps-ethernetlite (bz #1379298)

  - CVE-2016-7466: usb: xhci memory leakage during device
    unplug (bz #1377838)

  - CVE-2016-7422: virtio: NULL pointer dereference (bz
    #1376756)

  - CVE-2016-7908: net: Infinite loop in mcf_fec_do_tx (bz
    #1381193)

  - CVE-2016-8576: usb: xHCI: infinite loop vulnerability
    (bz #1382322)

  - CVE-2016-7995: usb: hcd-ehci: memory leak (bz #1382669)

  - Don't depend on edk2 roms where they aren't available
    (bz #1373576)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-a56fb613a8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 2:qemu package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:2:qemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC24", reference:"qemu-2.6.2-2.fc24", epoch:"2")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "2:qemu");
}
