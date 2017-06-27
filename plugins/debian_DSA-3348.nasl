#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3348. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85754);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/06/17 14:46:27 $");

  script_cve_id("CVE-2015-3214", "CVE-2015-5154", "CVE-2015-5165", "CVE-2015-5225", "CVE-2015-5745");
  script_osvdb_id(123468, 125389, 125706, 125847, 126595);
  script_xref(name:"DSA", value:"3348");

  script_name(english:"Debian DSA-3348-1 : qemu - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in qemu, a fast processor
emulator.

  - CVE-2015-3214
    Matt Tait of Google's Project Zero security team
    discovered a flaw in the QEMU i8254 PIT emulation. A
    privileged guest user in a guest with QEMU PIT emulation
    enabled could potentially use this flaw to execute
    arbitrary code on the host with the privileges of the
    hosting QEMU process.

  - CVE-2015-5154
    Kevin Wolf of Red Hat discovered a heap buffer overflow
    flaw in the IDE subsystem in QEMU while processing
    certain ATAPI commands. A privileged guest user in a
    guest with the CDROM drive enabled could potentially use
    this flaw to execute arbitrary code on the host with the
    privileges of the hosting QEMU process.

  - CVE-2015-5165
    Donghai Zhu discovered that the QEMU model of the
    RTL8139 network card did not sufficiently validate
    inputs in the C+ mode offload emulation, allowing a
    malicious guest to read uninitialized memory from the
    QEMU process's heap.

  - CVE-2015-5225
    Mr Qinghao Tang from QIHU 360 Inc. and Mr Zuozhi from
    Alibaba Inc discovered a buffer overflow flaw in the VNC
    display driver leading to heap memory corruption. A
    privileged guest user could use this flaw to mount a
    denial of service (QEMU process crash), or potentially
    to execute arbitrary code on the host with the
    privileges of the hosting QEMU process.

  - CVE-2015-5745
    A buffer overflow vulnerability was discovered in the
    way QEMU handles the virtio-serial device. A malicious
    guest could use this flaw to mount a denial of service
    (QEMU process crash)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=793811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=794610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=795087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=795461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=796465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3214"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5225"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-5745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/qemu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/qemu"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3348"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the qemu packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 1.1.2+dfsg-6a+deb7u9. The oldstable distribution is
only affected by CVE-2015-5165 and CVE-2015-5745.

For the stable distribution (jessie), these problems have been fixed
in version 1:2.1+dfsg-12+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"qemu", reference:"1.1.2+dfsg-6a+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-keymaps", reference:"1.1.2+dfsg-6a+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-system", reference:"1.1.2+dfsg-6a+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-user", reference:"1.1.2+dfsg-6a+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-user-static", reference:"1.1.2+dfsg-6a+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-utils", reference:"1.1.2+dfsg-6a+deb7u9")) flag++;
if (deb_check(release:"8.0", prefix:"qemu", reference:"1:2.1+dfsg-12+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-guest-agent", reference:"1:2.1+dfsg-12+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-kvm", reference:"1:2.1+dfsg-12+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system", reference:"1:2.1+dfsg-12+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-arm", reference:"1:2.1+dfsg-12+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-common", reference:"1:2.1+dfsg-12+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-mips", reference:"1:2.1+dfsg-12+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-misc", reference:"1:2.1+dfsg-12+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-ppc", reference:"1:2.1+dfsg-12+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-sparc", reference:"1:2.1+dfsg-12+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-system-x86", reference:"1:2.1+dfsg-12+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-user", reference:"1:2.1+dfsg-12+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-user-binfmt", reference:"1:2.1+dfsg-12+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-user-static", reference:"1:2.1+dfsg-12+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"qemu-utils", reference:"1:2.1+dfsg-12+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
