#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-574-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92004);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/06 20:03:52 $");

  script_cve_id("CVE-2015-5239", "CVE-2016-2857", "CVE-2016-4020", "CVE-2016-4439", "CVE-2016-5403", "CVE-2016-6351");
  script_osvdb_id(127119, 135305, 137159, 138741, 142100, 142178);

  script_name(english:"Debian DLA-574-1 : qemu-kvm security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in qemu-kvm, a full
virtualization solution on x86 hardware. The Common Vulnerabilities
and Exposures project identifies the following problems :

CVE-2015-5239

Lian Yihan discovered that QEMU incorrectly handled certain payload
messages in the VNC display driver. A malicious guest could use this
issue to cause the QEMU process to hang, resulting in a denial of
service.

CVE-2016-2857

Ling Liu discovered that QEMU incorrectly handled IP checksum
routines. An attacker inside the guest could use this issue to cause
QEMU to crash, resulting in a denial of service, or possibly leak host
memory bytes.

CVE-2016-4020

Donghai Zdh discovered that QEMU incorrectly handled the Task Priority
Register(TPR). A privileged attacker inside the guest could use this
issue to possibly leak host memory bytes.

CVE-2016-4439, CVE-2016-6351

Li Qiang disovered that the emulation of the 53C9X Fast SCSI
Controller is affected by out of bound access issues.

CVE-2016-5403

Zhenhao Hong discovered that a malicious guest administrator can cause
unbounded memory allocation in QEMU (which can cause an Out-of-Memory
condition) by submitting virtio requests without bothering to wait for
completion.

For Debian 7 'Wheezy', these problems have been fixed in version
1.1.2+dfsg-6+deb7u14.

We recommend that you upgrade your qemu-kvm packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/07/msg00035.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/qemu-kvm"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected kvm, qemu-kvm, and qemu-kvm-dbg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-kvm-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/12");
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
if (deb_check(release:"7.0", prefix:"kvm", reference:"1.1.2+dfsg-6+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-kvm", reference:"1.1.2+dfsg-6+deb7u14")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-kvm-dbg", reference:"1.1.2+dfsg-6+deb7u14")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
