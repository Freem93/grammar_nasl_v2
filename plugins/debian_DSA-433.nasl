#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-433. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15270);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/18 00:11:35 $");

  script_cve_id("CVE-2003-0961");
  script_bugtraq_id(9138);
  script_xref(name:"DSA", value:"433");

  script_name(english:"Debian DSA-433-1 : kernel-patch-2.4.17-mips - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Red Hat and SuSE kernel and security teams revealed an integer
overflow in the do_brk() function of the Linux kernel allows local
users to gain root privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-433"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kernel image packages for the mips and mipsel
architectures. This problem has been fixed in the upstream version
2.4.23 as well and is also fixed in 2.4.24, of course.

For the stable distribution (woody) this problem has been fixed in
version 2.4.17-0.020226.2.woody4. Other architectures are already or
will be fixed separately."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kernel-patch-2.4.17-mips");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"kernel-headers-2.4.17", reference:"2.4.17-0.020226.2.woody4")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.17-r3k-kn02", reference:"2.4.17-0.020226.2.woody4")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.17-r4k-ip22", reference:"2.4.17-0.020226.2.woody4")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.17-r4k-kn04", reference:"2.4.17-0.020226.2.woody4")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-image-2.4.17-r5k-ip22", reference:"2.4.17-0.020226.2.woody4")) flag++;
if (deb_check(release:"3.0", prefix:"kernel-patch-2.4.17-mips", reference:"2.4.17-0.020226.2.woody4")) flag++;
if (deb_check(release:"3.0", prefix:"mips-tools", reference:"2.4.17-0.020226.2.woody4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
