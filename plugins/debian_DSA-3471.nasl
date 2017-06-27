#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3471. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(88630);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2015-7295", "CVE-2015-7504", "CVE-2015-7512", "CVE-2015-7549", "CVE-2015-8345", "CVE-2015-8504", "CVE-2015-8550", "CVE-2015-8558", "CVE-2015-8567", "CVE-2015-8568", "CVE-2015-8613", "CVE-2015-8619", "CVE-2015-8743", "CVE-2015-8744", "CVE-2015-8745", "CVE-2016-1568", "CVE-2016-1714", "CVE-2016-1922", "CVE-2016-1981");
  script_osvdb_id(127769, 130703, 130888, 130889, 131399, 131668, 131793, 131824, 132029, 132136, 132210, 132257, 132466, 132467, 132549, 132550, 132759, 132798, 133524);
  script_xref(name:"DSA", value:"3471");

  script_name(english:"Debian DSA-3471-1 : qemu - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in qemu, a full virtualization
solution on x86 hardware.

  - CVE-2015-7295
    Jason Wang of Red Hat Inc. discovered that the Virtual
    Network Device support is vulnerable to
    denial-of-service, that could occur when receiving large
    packets.

  - CVE-2015-7504
    Qinghao Tang of Qihoo 360 Inc. and Ling Liu of Qihoo 360
    Inc. discovered that the PC-Net II ethernet controller
    is vulnerable to a heap-based buffer overflow that could
    result in denial-of-service (via application crash) or
    arbitrary code execution.

  - CVE-2015-7512
    Ling Liu of Qihoo 360 Inc. and Jason Wang of Red Hat
    Inc. discovered that the PC-Net II ethernet controller
    is vulnerable to a buffer overflow that could result in
    denial-of-service (via application crash) or arbitrary
    code execution.

  - CVE-2015-7549
    Qinghao Tang of Qihoo 360 Inc. and Ling Liu of Qihoo 360
    Inc. discovered that the PCI MSI-X emulator is
    vulnerable to a NULL pointer dereference issue, that
    could lead to denial-of-service (via application crash).

  - CVE-2015-8345
    Qinghao Tang of Qihoo 360 Inc. discovered that the
    eepro100 emulator contains a flaw that could lead to an
    infinite loop when processing Command Blocks, eventually
    resulting in denial-of-service (via application crash).

  - CVE-2015-8504
    Lian Yihan of Qihoo 360 Inc. discovered that the VNC
    display driver support is vulnerable to an arithmetic
    exception flaw that could lead to denial-of-service (via
    application crash).

  - CVE-2015-8550
    Felix Wilhelm of ERNW Research discovered that the PV
    backend drivers are vulnerable to double fetch
    vulnerabilities, possibly resulting in arbitrary code
    execution.

  - CVE-2015-8558
    Qinghao Tang of Qihoo 360 Inc. discovered that the USB
    EHCI emulation support contains a flaw that could lead
    to an infinite loop during communication between the
    host controller and a device driver. This could lead to
    denial-of-service (via resource exhaustion).

  - CVE-2015-8567 CVE-2015-8568
    Qinghao Tang of Qihoo 360 Inc. discovered that the
    vmxnet3 device emulator could be used to intentionally
    leak host memory, thus resulting in denial-of-service.

  - CVE-2015-8613
    Qinghao Tang of Qihoo 360 Inc. discovered that the SCSI
    MegaRAID SAS HBA emulation support is vulnerable to a
    stack-based buffer overflow issue, that could lead to
    denial-of-service (via application crash).

  - CVE-2015-8619
    Ling Liu of Qihoo 360 Inc. discovered that the Human
    Monitor Interface support is vulnerable to an
    out-of-bound write access issue that could result in
    denial-of-service (via application crash).

  - CVE-2015-8743
    Ling Liu of Qihoo 360 Inc. discovered that the NE2000
    emulator is vulnerable to an out-of-bound read/write
    access issue, potentially resulting in information leak
    or memory corruption.

  - CVE-2015-8744
    The vmxnet3 driver incorrectly processes small packets,
    which could result in denial-of-service (via application
    crash).

  - CVE-2015-8745
    The vmxnet3 driver incorrectly processes Interrupt Mask
    Registers, which could result in denial-of-service (via
    application crash).

  - CVE-2016-1568
    Qinghao Tang of Qihoo 360 Inc. discovered that the IDE
    AHCI emulation support is vulnerable to a use-after-free
    issue, that could lead to denial-of-service (via
    application crash) or arbitrary code execution.

  - CVE-2016-1714
    Donghai Zhu of Alibaba discovered that the Firmware
    Configuration emulation support is vulnerable to an
    out-of-bound read/write access issue, that could lead to
    denial-of-service (via application crash) or arbitrary
    code execution.

  - CVE-2016-1922
    Ling Liu of Qihoo 360 Inc. discovered that 32-bit
    Windows guests support is vulnerable to a NULL pointer
    dereference issue, that could lead to denial-of-service
    (via application crash).

  - CVE-2016-1981
    The e1000 driver is vulnerable to an infinite loop issue
    that could lead to denial-of-service (via application
    crash)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=799452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=806373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=806741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=806742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=808130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=808131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=808144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=808145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=809229"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=809232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=810519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=810527"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=811201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=812307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=809237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=809237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8744"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/qemu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3471"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the qemu packages.

For the stable distribution (jessie), these problems have been fixed
in version 1:2.1+dfsg-12+deb8u5a."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:X/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"qemu", reference:"1:2.1+dfsg-12+deb8u5a")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-guest-agent", reference:"1:2.1+dfsg-12+deb8u5a")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-kvm", reference:"1:2.1+dfsg-12+deb8u5a")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system", reference:"1:2.1+dfsg-12+deb8u5a")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-arm", reference:"1:2.1+dfsg-12+deb8u5a")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-common", reference:"1:2.1+dfsg-12+deb8u5a")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-mips", reference:"1:2.1+dfsg-12+deb8u5a")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-misc", reference:"1:2.1+dfsg-12+deb8u5a")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-ppc", reference:"1:2.1+dfsg-12+deb8u5a")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-sparc", reference:"1:2.1+dfsg-12+deb8u5a")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-x86", reference:"1:2.1+dfsg-12+deb8u5a")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-user", reference:"1:2.1+dfsg-12+deb8u5a")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-user-binfmt", reference:"1:2.1+dfsg-12+deb8u5a")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-user-static", reference:"1:2.1+dfsg-12+deb8u5a")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-utils", reference:"1:2.1+dfsg-12+deb8u5a")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
