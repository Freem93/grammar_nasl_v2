#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-479. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15316);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2004-0003", "CVE-2004-0010", "CVE-2004-0109", "CVE-2004-0177", "CVE-2004-0178");
  script_bugtraq_id(9570, 9691, 9985, 10141, 10152);
  script_xref(name:"DSA", value:"479");

  script_name(english:"Debian DSA-479-1 : linux-kernel-2.4.18-alpha+i386+powerpc - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several serious problems have been discovered in the Linux kernel.
This update takes care of Linux 2.4.18 for the alpha, i386 and powerpc
architectures. The Common Vulnerabilities and Exposures project
identifies the following problems that will be fixed with this update
:

  - CAN-2004-0003
    A vulnerability has been discovered in the R128 DRI
    driver in the Linux kernel which could potentially lead
    an attacker to gain unauthorised privileges. Alan Cox
    and Thomas Biege developed a correction for this.

  - CAN-2004-0010

    Arjan van de Ven discovered a stack-based buffer
    overflow in the ncp_lookup function for ncpfs in the
    Linux kernel, which could lead an attacker to gain
    unauthorised privileges. Petr Vandrovec developed a
    correction for this.

  - CAN-2004-0109

    zen-parse discovered a buffer overflow vulnerability in
    the ISO9660 filesystem component of Linux kernel which
    could be abused by an attacker to gain unauthorised root
    access. Sebastian Krahmer and Ernie Petrides developed a
    correction for this.

  - CAN-2004-0177

    Solar Designer discovered an information leak in the
    ext3 code of Linux. In a worst case an attacker could
    read sensitive data such as cryptographic keys which
    would otherwise never hit disk media. Theodore Ts'o
    developed a correction for this.

  - CAN-2004-0178

    Andreas Kies discovered a denial of service condition in
    the Sound Blaster driver in Linux. He also developed a
    correction for this.

These problems are also fixed by upstream in Linux 2.4.26 and will be
fixed in Linux 2.6.6.

The following security matrix explains which kernel versions for which
architectures are already fixed. Kernel images in the unstable Debian
distribution (sid) will be fixed soon.

  Architecture    stable (woody)  unstable (sid)  removed in sid  
  source          2.4.18-14.3     2.4.25-3        --             
  alpha           2.4.18-15       soon            --             
  i386            2.4.18-13       soon            --             
  i386bf          2.4.18-5woody8  soon            --             
  powerpc         2.4.18-1woody5  2.4.25-8        2.4.22"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-479"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kernel packages immediately, either with a Debian provided
kernel or with a self compiled one.

 Vulnerability matrix for CAN-2004-0109"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-source-2.4.18 kernel-image-2.4.18-1-alpha kernel-image-2.4.18-1-i386 kernel-image-2.4.18-i386bf kernel-patch-2.4.18-powerpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"kernel-doc-2.4.18", reference:"2.4.18-14.3")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18", reference:"2.4.18-1woody5")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1", reference:"2.4.18-13")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-386", reference:"2.4.18-13")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-586tsc", reference:"2.4.18-13")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-686", reference:"2.4.18-13")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-686-smp", reference:"2.4.18-13")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-generic", reference:"2.4.18-15")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-k6", reference:"2.4.18-13")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-k7", reference:"2.4.18-13")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-1-smp", reference:"2.4.18-15")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.18-bf2.4", reference:"2.4.18-5woody8")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-386", reference:"2.4.18-13")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-586tsc", reference:"2.4.18-13")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-686", reference:"2.4.18-13")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-686-smp", reference:"2.4.18-13")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-generic", reference:"2.4.18-15")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-k6", reference:"2.4.18-13")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-k7", reference:"2.4.18-13")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-1-smp", reference:"2.4.18-15")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-bf2.4", reference:"2.4.18-5woody8")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-newpmac", reference:"2.4.18-1woody5")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-powerpc", reference:"2.4.18-1woody5")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.18-powerpc-smp", reference:"2.4.18-1woody5")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-patch-2.4.18-powerpc", reference:"2.4.18-1woody5")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-386", reference:"2.4.18-13")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-586tsc", reference:"2.4.18-13")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-686", reference:"2.4.18-13")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-686-smp", reference:"2.4.18-13")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-k6", reference:"2.4.18-13")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-pcmcia-modules-2.4.18-1-k7", reference:"2.4.18-13")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-source-2.4.18", reference:"2.4.18-14.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
