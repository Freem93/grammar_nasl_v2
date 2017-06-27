#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1111. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22653);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/05/17 23:36:52 $");

  script_cve_id("CVE-2006-3626");
  script_osvdb_id(27120);
  script_xref(name:"DSA", value:"1111");

  script_name(english:"Debian DSA-1111-2 : kernel-source-2.6.8 - race condition");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that a race condition in the process filesystem can
lead to privilege escalation.

The following matrix explains which kernel version for which
architecture fixes the problem mentioned above :

                            Debian 3.1 (sarge)        
  Source                    2.6.8-16sarge4            
  Alpha architecture        2.6.8-16sarge4            
  AMD64 architecture        2.6.8-16sarge4            
  Intel IA-32 architecture  2.6.8-16sarge4            
  Intel IA-64 architecture  2.6.8-14sarge4            
  PowerPC architecture      2.6.8-12sarge4            
  Sun Sparc architecture    2.6.8-15sarge4            
  IBM S/390                 2.6.8-5sarge4             
  Motorola 680x0            2.6.8-4sarge4             
  HP Precision              2.6.8-6sarge3             
  FAI                       1.9.1sarge3               
The initial advisory lacked builds for the IBM S/390, Motorola 680x0
and HP Precision architectures, which are now provided. Also, the
kernels for the FAI installer have been updated."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1111"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kernel package immediately and reboot the machine. If you
have built a custom kernel from the kernel source package, you will
need to rebuild to take advantage of these fixes."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-source-2.6.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"fai-kernels", reference:"1.9.1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3", reference:"2.6.8-15sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-power3", reference:"2.6.8-12sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-power3-smp", reference:"2.6.8-12sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-power4", reference:"2.6.8-12sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-power4-smp", reference:"2.6.8-12sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-powerpc", reference:"2.6.8-12sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-build-2.6.8-3-powerpc-smp", reference:"2.6.8-12sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-doc-2.6.8", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-itanium", reference:"2.6.8-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-itanium-smp", reference:"2.6.8-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-mckinley", reference:"2.6.8-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6-mckinley-smp", reference:"2.6.8-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12-amd64-generic", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12-amd64-k8", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12-amd64-k8-smp", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12-em64t-p4", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-12-em64t-p4-smp", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3", reference:"2.6.8-15sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-32", reference:"2.6.8-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-32-smp", reference:"2.6.8-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-386", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-64", reference:"2.6.8-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-64-smp", reference:"2.6.8-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-686", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-686-smp", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-generic", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-itanium", reference:"2.6.8-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-itanium-smp", reference:"2.6.8-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-k7", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-k7-smp", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-mckinley", reference:"2.6.8-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-mckinley-smp", reference:"2.6.8-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-smp", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-sparc32", reference:"2.6.8-15sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-sparc64", reference:"2.6.8-15sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-headers-2.6.8-3-sparc64-smp", reference:"2.6.8-15sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-itanium", reference:"2.6.8-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-itanium-smp", reference:"2.6.8-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-mckinley", reference:"2.6.8-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6-mckinley-smp", reference:"2.6.8-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-12-amd64-generic", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-12-amd64-k8", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-12-amd64-k8-smp", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-12-em64t-p4", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-12-em64t-p4-smp", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-32", reference:"2.6.8-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-32-smp", reference:"2.6.8-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-386", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-64", reference:"2.6.8-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-64-smp", reference:"2.6.8-6sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-686", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-686-smp", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-generic", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-itanium", reference:"2.6.8-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-itanium-smp", reference:"2.6.8-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-k7", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-k7-smp", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-mckinley", reference:"2.6.8-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-mckinley-smp", reference:"2.6.8-14sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-power3", reference:"2.6.8-12sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-power3-smp", reference:"2.6.8-12sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-power4", reference:"2.6.8-12sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-power4-smp", reference:"2.6.8-12sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-powerpc", reference:"2.6.8-12sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-powerpc-smp", reference:"2.6.8-12sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-s390", reference:"2.6.8-5sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-s390-tape", reference:"2.6.8-5sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-s390x", reference:"2.6.8-5sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-smp", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-sparc32", reference:"2.6.8-15sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-sparc64", reference:"2.6.8-15sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-3-sparc64-smp", reference:"2.6.8-15sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-amiga", reference:"2.6.8-4sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-atari", reference:"2.6.8-4sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-bvme6000", reference:"2.6.8-4sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-hp", reference:"2.6.8-4sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mac", reference:"2.6.8-4sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mvme147", reference:"2.6.8-4sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-mvme16x", reference:"2.6.8-4sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-q40", reference:"2.6.8-4sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-image-2.6.8-sun3", reference:"2.6.8-4sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-2.6.8-s390", reference:"2.6.8-5sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-patch-debian-2.6.8", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-source-2.6.8", reference:"2.6.8-16sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"kernel-tree-2.6.8", reference:"2.6.8-16sarge4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
