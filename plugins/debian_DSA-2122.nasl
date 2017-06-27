#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2122. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50309);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/12/03 12:08:28 $");

  script_cve_id("CVE-2010-3847", "CVE-2010-3856");
  script_bugtraq_id(44154);
  script_osvdb_id(68721, 68920);
  script_xref(name:"DSA", value:"2122");

  script_name(english:"Debian DSA-2122-1 : glibc - missing input sanitization");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ben Hawkes and Tavis Ormandy discovered that the dynamic loader in GNU
libc allows local users to gain root privileges using a crafted
LD_AUDIT environment variable."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=600667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2122"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the glibc packages.

For the stable distribution (lenny), this problem has been fixed in
version 2.7-18lenny6.

For the upcoming stable distribution (squeeze), this problem has been
fixed in version 2.11.2-6+squeeze1 of the eglibc package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"glibc-doc", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"glibc-source", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-amd64", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-dbg", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-dev", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-dev-amd64", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-dev-i386", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-dev-mips64", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-dev-mipsn32", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-dev-ppc64", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-dev-s390x", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-dev-sparc64", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-i386", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-i686", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-mips64", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-mipsn32", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-pic", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-ppc64", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-prof", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-s390x", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-sparc64", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-sparcv9b", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-xen", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6.1", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6.1-alphaev67", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6.1-dbg", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6.1-dev", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6.1-pic", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libc6.1-prof", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"locales", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"locales-all", reference:"2.7-18lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"nscd", reference:"2.7-18lenny6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
