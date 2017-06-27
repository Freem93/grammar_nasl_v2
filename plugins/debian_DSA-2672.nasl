#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2672. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66548);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/16 15:37:40 $");

  script_cve_id("CVE-2013-3266");
  script_bugtraq_id(59585);
  script_xref(name:"DSA", value:"2672");

  script_name(english:"Debian DSA-2672-1 : kfreebsd-9 - interpretation conflict");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Adam Nowacki discovered that the new FreeBSD NFS implementation
processes a crafted READDIR request which instructs to operate a file
system on a file node as if it were a directory node, leading to a
kernel crash or potentially arbitrary code execution.

The kfreebsd-8 kernel in the oldstable distribution (squeeze) does not
enable the new NFS implementation. The Linux kernel is not affected by
this vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=706414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/kfreebsd-9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2672"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kfreebsd-9 packages.

For the stable distribution (wheezy), this problem has been fixed in
version 9.0-10+deb70.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kfreebsd-9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9-486", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9-686", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9-686-smp", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9-amd64", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9-malta", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9-xen", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9.0-2", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9.0-2-486", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9.0-2-686", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9.0-2-686-smp", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9.0-2-amd64", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9.0-2-malta", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9.0-2-xen", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9-486", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9-686", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9-686-smp", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9-amd64", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9-malta", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9-xen", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9.0-2-486", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9.0-2-686", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9.0-2-686-smp", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9.0-2-amd64", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9.0-2-malta", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9.0-2-xen", reference:"9.0-10+deb70.1")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-source-9.0", reference:"9.0-10+deb70.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
