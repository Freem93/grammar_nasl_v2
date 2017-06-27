#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1479. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30126);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/03/19 14:28:18 $");

  script_cve_id("CVE-2007-2878", "CVE-2007-4571", "CVE-2007-6151", "CVE-2008-0001");
  script_bugtraq_id(25807, 27280);
  script_osvdb_id(39234, 40913);
  script_xref(name:"DSA", value:"1479");

  script_name(english:"Debian DSA-1479-1 : linux-2.6 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several local vulnerabilities have been discovered in the Linux kernel
that may lead to a denial of service or the execution of arbitrary
code. The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2007-2878
    Bart Oldeman reported a denial of service (DoS) issue in
    the VFAT filesystem that allows local users to corrupt a
    kernel structure resulting in a system crash. This is
    only an issue for systems which make use of the VFAT
    compat ioctl interface, such as systems running an
    'amd64' flavor kernel.

  - CVE-2007-4571
    Takashi Iwai supplied a fix for a memory leak in the
    snd_page_alloc module. Local users could exploit this
    issue to obtain sensitive information from the kernel.

  - CVE-2007-6151
    ADLAB discovered a possible memory overrun in the ISDN
    subsystem that may permit a local user to overwrite
    kernel memory by issuing ioctls with unterminated data.

  - CVE-2008-0001
    Bill Roman of Datalight noticed a coding error in the
    linux VFS subsystem that, under certain conditions, can
    allow local users to remove directories for which they
    should not have removal privileges.

These problems have been fixed in the stable distribution in version
2.6.18.dfsg.1-17etch1."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6151"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1479"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kernel packages immediately and reboot the machine. If you
have built a custom kernel from the kernel source package, you will
need to rebuild to take advantage of these fixes."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-2.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"fai-kernels", reference:"1.17+etch.17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"gspca-modules-2.6-486", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gspca-modules-2.6-686", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gspca-modules-2.6-686-bigmem", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gspca-modules-2.6-amd64", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gspca-modules-2.6-k7", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gspca-modules-2.6-vserver-686", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gspca-modules-2.6-vserver-k7", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gspca-modules-2.6-xen-686", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gspca-modules-2.6-xen-vserver-686", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gspca-modules-2.6.18-6-486", reference:"2.6.18+01.00.04-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gspca-modules-2.6.18-6-686", reference:"2.6.18+01.00.04-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gspca-modules-2.6.18-6-686-bigmem", reference:"2.6.18+01.00.04-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gspca-modules-2.6.18-6-amd64", reference:"2.6.18+01.00.04-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gspca-modules-2.6.18-6-k7", reference:"2.6.18+01.00.04-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gspca-modules-2.6.18-6-vserver-686", reference:"2.6.18+01.00.04-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gspca-modules-2.6.18-6-vserver-k7", reference:"2.6.18+01.00.04-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gspca-modules-2.6.18-6-xen-686", reference:"2.6.18+01.00.04-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"gspca-modules-2.6.18-6-xen-vserver-686", reference:"2.6.18+01.00.04-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2100-modules-2.6-486", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2100-modules-2.6-686", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2100-modules-2.6-686-bigmem", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2100-modules-2.6-amd64", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2100-modules-2.6-k7", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2100-modules-2.6-vserver-686", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2100-modules-2.6-vserver-k7", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2100-modules-2.6-xen-686", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2100-modules-2.6-xen-vserver-686", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2100-modules-2.6.18-6-486", reference:"2.6.18+1.2.1-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2100-modules-2.6.18-6-686", reference:"2.6.18+1.2.1-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2100-modules-2.6.18-6-686-bigmem", reference:"2.6.18+1.2.1-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2100-modules-2.6.18-6-amd64", reference:"2.6.18+1.2.1-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2100-modules-2.6.18-6-k7", reference:"2.6.18+1.2.1-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2100-modules-2.6.18-6-vserver-686", reference:"2.6.18+1.2.1-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2100-modules-2.6.18-6-vserver-k7", reference:"2.6.18+1.2.1-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2100-modules-2.6.18-6-xen-686", reference:"2.6.18+1.2.1-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2100-modules-2.6.18-6-xen-vserver-686", reference:"2.6.18+1.2.1-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2200-modules-2.6-486", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2200-modules-2.6-686", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2200-modules-2.6-686-bigmem", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2200-modules-2.6-amd64", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2200-modules-2.6-k7", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2200-modules-2.6-vserver-686", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2200-modules-2.6-vserver-k7", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2200-modules-2.6-xen-686", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2200-modules-2.6-xen-vserver-686", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2200-modules-2.6.18-6-486", reference:"2.6.18+1.2.0-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2200-modules-2.6.18-6-686", reference:"2.6.18+1.2.0-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2200-modules-2.6.18-6-686-bigmem", reference:"2.6.18+1.2.0-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2200-modules-2.6.18-6-amd64", reference:"2.6.18+1.2.0-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2200-modules-2.6.18-6-k7", reference:"2.6.18+1.2.0-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2200-modules-2.6.18-6-vserver-686", reference:"2.6.18+1.2.0-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2200-modules-2.6.18-6-vserver-k7", reference:"2.6.18+1.2.0-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2200-modules-2.6.18-6-xen-686", reference:"2.6.18+1.2.0-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw2200-modules-2.6.18-6-xen-vserver-686", reference:"2.6.18+1.2.0-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw3945-modules-2.6-486", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw3945-modules-2.6-686", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw3945-modules-2.6-686-bigmem", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw3945-modules-2.6-amd64", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw3945-modules-2.6-k7", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw3945-modules-2.6-vserver-686", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw3945-modules-2.6-vserver-k7", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw3945-modules-2.6-xen-686", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw3945-modules-2.6-xen-vserver-686", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw3945-modules-2.6.18-6-486", reference:"2.6.18+1.1.2-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw3945-modules-2.6.18-6-686", reference:"2.6.18+1.1.2-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw3945-modules-2.6.18-6-686-bigmem", reference:"2.6.18+1.1.2-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw3945-modules-2.6.18-6-amd64", reference:"2.6.18+1.1.2-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw3945-modules-2.6.18-6-k7", reference:"2.6.18+1.1.2-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw3945-modules-2.6.18-6-vserver-686", reference:"2.6.18+1.1.2-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw3945-modules-2.6.18-6-vserver-k7", reference:"2.6.18+1.1.2-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw3945-modules-2.6.18-6-xen-686", reference:"2.6.18+1.1.2-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ipw3945-modules-2.6.18-6-xen-vserver-686", reference:"2.6.18+1.1.2-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ivtv-modules-2.6-486", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ivtv-modules-2.6-686", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ivtv-modules-2.6-686-bigmem", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ivtv-modules-2.6-amd64", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ivtv-modules-2.6-k7", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ivtv-modules-2.6-vserver-686", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ivtv-modules-2.6-vserver-k7", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ivtv-modules-2.6-xen-686", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ivtv-modules-2.6-xen-vserver-686", reference:"2.6.18-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ivtv-modules-2.6.18-6-486", reference:"2.6.18+0.8.2-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ivtv-modules-2.6.18-6-686", reference:"2.6.18+0.8.2-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ivtv-modules-2.6.18-6-686-bigmem", reference:"2.6.18+0.8.2-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ivtv-modules-2.6.18-6-amd64", reference:"2.6.18+0.8.2-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ivtv-modules-2.6.18-6-k7", reference:"2.6.18+0.8.2-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ivtv-modules-2.6.18-6-vserver-686", reference:"2.6.18+0.8.2-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ivtv-modules-2.6.18-6-vserver-k7", reference:"2.6.18+0.8.2-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ivtv-modules-2.6.18-6-xen-686", reference:"2.6.18+0.8.2-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ivtv-modules-2.6.18-6-xen-vserver-686", reference:"2.6.18+0.8.2-4+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-386", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-686", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-686-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-amd64-generic", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-amd64-k8", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-amd64-k8-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-em64t-p4", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-em64t-p4-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-generic", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-itanium", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-itanium-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-k7", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-k7-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-mckinley", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-mckinley-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-power3", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-power3-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-power4", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-power4-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-powerpc", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-powerpc-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-s390", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-s390x", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-sparc64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-2.6-sparc64-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-power3", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-power3-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-power4", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-power4-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-powerpc", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kernel-image-powerpc-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kqemu-modules-2.6-486", reference:"2.6.18-4etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kqemu-modules-2.6-686", reference:"2.6.18-4etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kqemu-modules-2.6-686-bigmem", reference:"2.6.18-4etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kqemu-modules-2.6-k7", reference:"2.6.18-4etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kqemu-modules-2.6.18-6-486", reference:"2.6.18+1.3.0~pre9-4etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kqemu-modules-2.6.18-6-686", reference:"2.6.18+1.3.0~pre9-4etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kqemu-modules-2.6.18-6-686-bigmem", reference:"2.6.18+1.3.0~pre9-4etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kqemu-modules-2.6.18-6-k7", reference:"2.6.18+1.3.0~pre9-4etch2")) flag++;
if (deb_check(release:"4.0", prefix:"linux-doc-2.6.18", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-486", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-686", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-686-bigmem", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-alpha-generic", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-alpha-legacy", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-alpha-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-amd64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-footbridge", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-iop32x", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-itanium", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-ixp4xx", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-k7", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-mckinley", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-parisc", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-parisc-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-parisc64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-parisc64-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-powerpc", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-powerpc-miboot", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-powerpc-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-powerpc64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-prep", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-qemu", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-r3k-kn02", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-r4k-ip22", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-r4k-kn04", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-r5k-cobalt", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-r5k-ip32", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-rpc", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-s390", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-s390x", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-s3c2410", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-sb1-bcm91250a", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-sb1a-bcm91480b", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-sparc32", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-sparc64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-sparc64-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-vserver-686", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-vserver-alpha", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-vserver-amd64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-vserver-k7", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-vserver-powerpc", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-vserver-powerpc64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-vserver-s390x", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-vserver-sparc64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-xen-686", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-xen-amd64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-xen-vserver-686", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6-xen-vserver-amd64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-486", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-686", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-686-bigmem", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-alpha", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-amd64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-arm", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-hppa", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-i386", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-ia64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-mips", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-mipsel", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-powerpc", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-s390", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-all-sparc", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-alpha-generic", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-alpha-legacy", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-alpha-smp", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-amd64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-footbridge", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-iop32x", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-itanium", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-ixp4xx", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-k7", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-mckinley", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-parisc", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-parisc-smp", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-parisc64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-parisc64-smp", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-powerpc", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-powerpc-miboot", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-powerpc-smp", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-powerpc64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-prep", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-qemu", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-r3k-kn02", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-r4k-ip22", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-r4k-kn04", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-r5k-cobalt", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-r5k-ip32", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-rpc", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-s390", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-s390x", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-s3c2410", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-sb1-bcm91250a", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-sb1a-bcm91480b", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-sparc32", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-sparc64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-sparc64-smp", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-686", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-alpha", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-amd64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-k7", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-powerpc", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-powerpc64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-s390x", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-vserver-sparc64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-686", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-amd64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-vserver", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-vserver-686", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-headers-2.6.18-6-xen-vserver-amd64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-486", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-686", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-686-bigmem", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-686-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-alpha-generic", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-alpha-legacy", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-alpha-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-amd64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-amd64-generic", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-amd64-k8", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-amd64-k8-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-em64t-p4", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-em64t-p4-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-footbridge", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-iop32x", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-itanium", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-itanium-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-ixp4xx", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-k7", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-k7-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-mckinley", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-mckinley-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-parisc", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-parisc-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-parisc64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-parisc64-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-powerpc", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-powerpc-miboot", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-powerpc-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-powerpc64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-prep", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-qemu", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-r3k-kn02", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-r4k-ip22", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-r4k-kn04", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-r5k-cobalt", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-r5k-ip32", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-rpc", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-s390", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-s390-tape", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-s390x", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-s3c2410", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-sb1-bcm91250a", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-sb1a-bcm91480b", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-sparc32", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-sparc64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-sparc64-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-vserver-686", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-vserver-alpha", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-vserver-amd64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-vserver-amd64-k8-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-vserver-em64t-p4-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-vserver-k7", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-vserver-powerpc", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-vserver-powerpc64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-vserver-s390x", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-vserver-sparc64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-xen-686", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-xen-amd64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-xen-vserver-686", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6-xen-vserver-amd64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-486", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-686", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-686-bigmem", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-alpha-generic", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-alpha-legacy", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-alpha-smp", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-amd64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-footbridge", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-iop32x", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-itanium", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-ixp4xx", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-k7", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-mckinley", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-parisc", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-parisc-smp", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-parisc64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-parisc64-smp", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-powerpc", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-powerpc-miboot", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-powerpc-smp", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-powerpc64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-prep", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-qemu", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-r3k-kn02", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-r4k-ip22", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-r4k-kn04", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-r5k-cobalt", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-r5k-ip32", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-rpc", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-s390", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-s390-tape", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-s390x", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-s3c2410", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-sb1-bcm91250a", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-sb1a-bcm91480b", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-sparc32", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-sparc64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-sparc64-smp", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-686", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-alpha", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-amd64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-k7", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-powerpc", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-powerpc64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-s390x", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-vserver-sparc64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-xen-686", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-xen-amd64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-xen-vserver-686", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-2.6.18-6-xen-vserver-amd64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-486", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-686", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-686-bigmem", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-alpha-generic", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-alpha-legacy", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-alpha-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-amd64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-footbridge", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-iop32x", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-itanium", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-ixp4xx", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-k7", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-mckinley", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-parisc", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-parisc-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-parisc64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-parisc64-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-powerpc", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-powerpc-miboot", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-powerpc-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-powerpc64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-prep", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-qemu", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-r3k-kn02", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-r4k-ip22", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-r4k-kn04", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-r5k-cobalt", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-r5k-ip32", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-rpc", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-s390", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-s390-tape", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-s390x", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-s3c2410", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-sb1-bcm91250a", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-sb1a-bcm91480b", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-sparc32", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-sparc64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-sparc64-smp", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-vserver-686", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-vserver-alpha", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-vserver-amd64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-vserver-k7", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-vserver-powerpc", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-vserver-powerpc64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-vserver-s390x", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-vserver-sparc64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-xen-686", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-xen-amd64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-xen-vserver-686", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-image-xen-vserver-amd64", reference:"2.6.18+6etch3")) flag++;
if (deb_check(release:"4.0", prefix:"linux-manual-2.6.18", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-6-xen-686", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-6-xen-amd64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-6-xen-vserver-686", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-modules-2.6.18-6-xen-vserver-amd64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-patch-debian-2.6.18", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-source-2.6.18", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-support-2.6.18-6", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"linux-tree-2.6.18", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"loop-aes-modules-2.6-486", reference:"3.1d-13etch2")) flag++;
if (deb_check(release:"4.0", prefix:"loop-aes-modules-2.6-686", reference:"3.1d-13etch2")) flag++;
if (deb_check(release:"4.0", prefix:"loop-aes-modules-2.6-686-bigmem", reference:"3.1d-13etch2")) flag++;
if (deb_check(release:"4.0", prefix:"loop-aes-modules-2.6-amd64", reference:"3.1d-13etch2")) flag++;
if (deb_check(release:"4.0", prefix:"loop-aes-modules-2.6-k7", reference:"3.1d-13etch2")) flag++;
if (deb_check(release:"4.0", prefix:"loop-aes-modules-2.6-vserver-686", reference:"3.1d-13etch2")) flag++;
if (deb_check(release:"4.0", prefix:"loop-aes-modules-2.6-vserver-k7", reference:"3.1d-13etch2")) flag++;
if (deb_check(release:"4.0", prefix:"loop-aes-modules-2.6-xen-686", reference:"3.1d-13etch2")) flag++;
if (deb_check(release:"4.0", prefix:"loop-aes-modules-2.6-xen-vserver-686", reference:"3.1d-13etch2")) flag++;
if (deb_check(release:"4.0", prefix:"loop-aes-modules-2.6.18-6-486", reference:"3.1d-13etch2")) flag++;
if (deb_check(release:"4.0", prefix:"loop-aes-modules-2.6.18-6-686", reference:"3.1d-13etch2")) flag++;
if (deb_check(release:"4.0", prefix:"loop-aes-modules-2.6.18-6-686-bigmem", reference:"3.1d-13etch2")) flag++;
if (deb_check(release:"4.0", prefix:"loop-aes-modules-2.6.18-6-amd64", reference:"3.1d-13etch2")) flag++;
if (deb_check(release:"4.0", prefix:"loop-aes-modules-2.6.18-6-k7", reference:"3.1d-13etch2")) flag++;
if (deb_check(release:"4.0", prefix:"loop-aes-modules-2.6.18-6-vserver-686", reference:"3.1d-13etch2")) flag++;
if (deb_check(release:"4.0", prefix:"loop-aes-modules-2.6.18-6-vserver-k7", reference:"3.1d-13etch2")) flag++;
if (deb_check(release:"4.0", prefix:"loop-aes-modules-2.6.18-6-xen-686", reference:"3.1d-13etch2")) flag++;
if (deb_check(release:"4.0", prefix:"loop-aes-modules-2.6.18-6-xen-vserver-686", reference:"3.1d-13etch2")) flag++;
if (deb_check(release:"4.0", prefix:"loop-aes-source", reference:"3.1d-13etch2")) flag++;
if (deb_check(release:"4.0", prefix:"loop-aes-testsuite", reference:"3.1d-13etch2")) flag++;
if (deb_check(release:"4.0", prefix:"nvidia-kernel-2.6-486", reference:"1.0.8776+6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"nvidia-kernel-2.6-686", reference:"1.0.8776+6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"nvidia-kernel-2.6-amd64", reference:"1.0.8776+6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"nvidia-kernel-2.6-k7", reference:"1.0.8776+6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"nvidia-kernel-2.6.18-6-486", reference:"1.0.8776+6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"nvidia-kernel-2.6.18-6-686", reference:"1.0.8776+6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"nvidia-kernel-2.6.18-6-amd64", reference:"1.0.8776+6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"nvidia-kernel-2.6.18-6-k7", reference:"1.0.8776+6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"nvidia-kernel-legacy-2.6-486", reference:"1.0.7184+6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"nvidia-kernel-legacy-2.6-686", reference:"1.0.7184+6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"nvidia-kernel-legacy-2.6-amd64", reference:"1.0.7184+6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"nvidia-kernel-legacy-2.6-k7", reference:"1.0.7184+6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"nvidia-kernel-legacy-2.6.18-6-486", reference:"1.0.7184+6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"nvidia-kernel-legacy-2.6.18-6-686", reference:"1.0.7184+6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"nvidia-kernel-legacy-2.6.18-6-amd64", reference:"1.0.7184+6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"nvidia-kernel-legacy-2.6.18-6-k7", reference:"1.0.7184+6etch2")) flag++;
if (deb_check(release:"4.0", prefix:"redhat-cluster-modules-2.6-486", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"redhat-cluster-modules-2.6-686", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"redhat-cluster-modules-2.6-686-bigmem", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"redhat-cluster-modules-2.6-amd64", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"redhat-cluster-modules-2.6-k7", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"redhat-cluster-modules-2.6-vserver-686", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"redhat-cluster-modules-2.6-vserver-k7", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"redhat-cluster-modules-2.6-xen-686", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"redhat-cluster-modules-2.6-xen-vserver-686", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"redhat-cluster-modules-2.6.18-6-486", reference:"2.6.18+1.03.00-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"redhat-cluster-modules-2.6.18-6-686", reference:"2.6.18+1.03.00-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"redhat-cluster-modules-2.6.18-6-686-bigmem", reference:"2.6.18+1.03.00-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"redhat-cluster-modules-2.6.18-6-amd64", reference:"2.6.18+1.03.00-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"redhat-cluster-modules-2.6.18-6-k7", reference:"2.6.18+1.03.00-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"redhat-cluster-modules-2.6.18-6-vserver-686", reference:"2.6.18+1.03.00-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"redhat-cluster-modules-2.6.18-6-vserver-k7", reference:"2.6.18+1.03.00-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"redhat-cluster-modules-2.6.18-6-xen-686", reference:"2.6.18+1.03.00-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"redhat-cluster-modules-2.6.18-6-xen-vserver-686", reference:"2.6.18+1.03.00-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"squashfs-modules-2.6-486", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"squashfs-modules-2.6-686", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"squashfs-modules-2.6-686-bigmem", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"squashfs-modules-2.6-amd64", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"squashfs-modules-2.6-k7", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"squashfs-modules-2.6-vserver-686", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"squashfs-modules-2.6-vserver-k7", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"squashfs-modules-2.6-xen-686", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"squashfs-modules-2.6-xen-vserver-686", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"squashfs-modules-2.6.18-6-486", reference:"2.6.18+3.1r2-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"squashfs-modules-2.6.18-6-686", reference:"2.6.18+3.1r2-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"squashfs-modules-2.6.18-6-686-bigmem", reference:"2.6.18+3.1r2-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"squashfs-modules-2.6.18-6-amd64", reference:"2.6.18+3.1r2-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"squashfs-modules-2.6.18-6-k7", reference:"2.6.18+3.1r2-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"squashfs-modules-2.6.18-6-vserver-686", reference:"2.6.18+3.1r2-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"squashfs-modules-2.6.18-6-vserver-k7", reference:"2.6.18+3.1r2-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"squashfs-modules-2.6.18-6-xen-686", reference:"2.6.18+3.1r2-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"squashfs-modules-2.6.18-6-xen-vserver-686", reference:"2.6.18+3.1r2-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"unionfs-modules-2.6-486", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"unionfs-modules-2.6-686", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"unionfs-modules-2.6-686-bigmem", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"unionfs-modules-2.6-amd64", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"unionfs-modules-2.6-k7", reference:"2.6.18-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"unionfs-modules-2.6.18-6-486", reference:"2.6.18+1.4+debian-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"unionfs-modules-2.6.18-6-686", reference:"2.6.18+1.4+debian-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"unionfs-modules-2.6.18-6-686-bigmem", reference:"2.6.18+1.4+debian-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"unionfs-modules-2.6.18-6-amd64", reference:"2.6.18+1.4+debian-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"unionfs-modules-2.6.18-6-k7", reference:"2.6.18+1.4+debian-7+etch4")) flag++;
if (deb_check(release:"4.0", prefix:"user-mode-linux", reference:"2.6.18-1um-2etch.17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-6-xen-686", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-6-xen-amd64", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-6-xen-vserver-686", reference:"2.6.18.dfsg.1-17etch1")) flag++;
if (deb_check(release:"4.0", prefix:"xen-linux-system-2.6.18-6-xen-vserver-amd64", reference:"2.6.18.dfsg.1-17etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
