#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3349. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85755);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/06/17 14:46:27 $");

  script_cve_id("CVE-2015-5165", "CVE-2015-5745");
  script_osvdb_id(125706, 125847);
  script_xref(name:"DSA", value:"3349");

  script_name(english:"Debian DSA-3349-1 : qemu-kvm - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in qemu-kvm, a full
virtualization solution on x86 hardware.

  - CVE-2015-5165
    Donghai Zhu discovered that the QEMU model of the
    RTL8139 network card did not sufficiently validate
    inputs in the C+ mode offload emulation, allowing a
    malicious guest to read uninitialized memory from the
    QEMU process's heap.

  - CVE-2015-5745
    A buffer overflow vulnerability was discovered in the
    way QEMU handles the virtio-serial device. A malicious
    guest could use this flaw to mount a denial of service
    (QEMU process crash)."
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
    value:"https://packages.debian.org/source/wheezy/qemu-kvm"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3349"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the qemu-kvm packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 1.1.2+dfsg-6+deb7u9."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

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
if (deb_check(release:"7.0", prefix:"kvm", reference:"1.1.2+dfsg-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-kvm", reference:"1.1.2+dfsg-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"qemu-kvm-dbg", reference:"1.1.2+dfsg-6+deb7u9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
