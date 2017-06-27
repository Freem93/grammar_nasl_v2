#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-12394e2cc7.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(96782);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/01/30 15:10:03 $");

  script_cve_id("CVE-2016-10028", "CVE-2016-6836", "CVE-2016-7909", "CVE-2016-7994", "CVE-2016-8577", "CVE-2016-8578", "CVE-2016-8668", "CVE-2016-8669", "CVE-2016-8909", "CVE-2016-8910", "CVE-2016-9101", "CVE-2016-9102", "CVE-2016-9103", "CVE-2016-9104", "CVE-2016-9105", "CVE-2016-9106", "CVE-2016-9381", "CVE-2016-9776", "CVE-2016-9845", "CVE-2016-9846", "CVE-2016-9907", "CVE-2016-9908", "CVE-2016-9911", "CVE-2016-9912", "CVE-2016-9913", "CVE-2016-9921");
  script_xref(name:"FEDORA", value:"2017-12394e2cc7");

  script_name(english:"Fedora 24 : 2:qemu (2017-12394e2cc7)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - CVE-2016-6836: vmxnet: Information leakage in
    vmxnet3_complete_packet (bz #1366370)

  - CVE-2016-7909: pcnet: Infinite loop in pcnet_rdra_addr
    (bz #1381196)

  - CVE-2016-7994: virtio-gpu: memory leak in
    resource_create_2d (bz #1382667)

  - CVE-2016-8577: 9pfs: host memory leakage in v9fs_read
    (bz #1383286)

  - CVE-2016-8578: 9pfs: potential NULL dereferencein 9pfs
    routines (bz #1383292)

  - CVE-2016-8668: OOB buffer access in rocker switch
    emulation (bz #1384898)

  - CVE-2016-8669: divide by zero error in
    serial_update_parameters (bz #1384911)

  - CVE-2016-8910: rtl8139: infinite loop while transmit in
    C+ mode (bz #1388047)

  - CVE-2016-8909: intel-hda: infinite loop in dma buffer
    stream (bz #1388053)

  - Infinite loop vulnerability in a9_gtimer_update (bz
    #1388300)

  - CVE-2016-9101: eepro100: memory leakage at device unplug
    (bz #1389539)

  - CVE-2016-9103: 9pfs: information leakage via xattr (bz
    #1389643)

  - CVE-2016-9102: 9pfs: memory leakage when creating
    extended attribute (bz #1389551)

  - CVE-2016-9104: 9pfs: integer overflow leading to OOB
    access (bz #1389687)

  - CVE-2016-9105: 9pfs: memory leakage in v9fs_link (bz
    #1389704)

  - CVE-2016-9106: 9pfs: memory leakage in v9fs_write (bz
    #1389713)

  - CVE-2016-9381: xen: incautious about shared ring
    processing (bz #1397385)

  - CVE-2016-9921: Divide by zero vulnerability in
    cirrus_do_copy (bz #1399054)

  - CVE-2016-9776: infinite loop while receiving data in
    mcf_fec_receive (bz #1400830)

  - CVE-2016-9845: information leakage in
    virgl_cmd_get_capset_info (bz #1402247)

  - CVE-2016-9846: virtio-gpu: memory leakage while updating
    cursor data (bz #1402258)

  - CVE-2016-9907: usbredir: memory leakage when destroying
    redirector (bz #1402266)

  - CVE-2016-9911: usb: ehci: memory leakage in
    ehci_init_transfer (bz #1402273)

  - CVE-2016-9913: 9pfs: memory leakage via proxy/handle
    callbacks (bz #1402277)

  - CVE-2016-10028: virtio-gpu-3d: OOB access while reading
    virgl capabilities (bz #1406368)

  - CVE-2016-9908: virtio-gpu: information leakage in
    virgl_cmd_get_capset (bz #1402263)

  - CVE-2016-9912: virtio-gpu: memory leakage when
    destroying gpu resource (bz #1402285)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-12394e2cc7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 2:qemu package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:2:qemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC24", reference:"qemu-2.6.2-6.fc24", epoch:"2")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
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
