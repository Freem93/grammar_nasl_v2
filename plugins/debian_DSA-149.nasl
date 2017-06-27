#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-149. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14986);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/17 23:45:45 $");

  script_cve_id("CVE-2002-0391");
  script_bugtraq_id(5356);
  script_xref(name:"CERT", value:"192995");
  script_xref(name:"DSA", value:"149");

  script_name(english:"Debian DSA-149-1 : glibc - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An integer overflow bug has been discovered in the RPC library used by
GNU libc, which is derived from the SunRPC library. This bug could be
exploited to gain unauthorized root access to software linking to this
code. The packages below also fix integer overflows in the malloc
code. They also contain a fix from Andreas Schwab to reduce linebuflen
in parallel to bumping up the buffer pointer in the NSS DNS code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-149"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libc6 packages immediately.

This problem has been fixed in version 2.1.3-23 for the old stable
distribution (potato), in version 2.2.5-11.1 for the current stable
distribution (woody) and in version 2.2.5-13 for the unstable
distribution (sid)."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/08/13");
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
if (deb_check(release:"2.2", prefix:"glibc-doc", reference:"2.1.3-24")) flag++;
if (deb_check(release:"2.2", prefix:"i18ndata", reference:"2.1.3-24")) flag++;
if (deb_check(release:"2.2", prefix:"libc6", reference:"2.1.3-24")) flag++;
if (deb_check(release:"2.2", prefix:"libc6-dbg", reference:"2.1.3-24")) flag++;
if (deb_check(release:"2.2", prefix:"libc6-dev", reference:"2.1.3-24")) flag++;
if (deb_check(release:"2.2", prefix:"libc6-pic", reference:"2.1.3-24")) flag++;
if (deb_check(release:"2.2", prefix:"libc6-prof", reference:"2.1.3-24")) flag++;
if (deb_check(release:"2.2", prefix:"libc6.1", reference:"2.1.3-24")) flag++;
if (deb_check(release:"2.2", prefix:"libc6.1-dbg", reference:"2.1.3-24")) flag++;
if (deb_check(release:"2.2", prefix:"libc6.1-dev", reference:"2.1.3-24")) flag++;
if (deb_check(release:"2.2", prefix:"libc6.1-pic", reference:"2.1.3-24")) flag++;
if (deb_check(release:"2.2", prefix:"libc6.1-prof", reference:"2.1.3-24")) flag++;
if (deb_check(release:"2.2", prefix:"libnss1-compat", reference:"2.1.3-24")) flag++;
if (deb_check(release:"2.2", prefix:"locales", reference:"2.1.3-24")) flag++;
if (deb_check(release:"2.2", prefix:"nscd", reference:"2.1.3-24")) flag++;
if (deb_check(release:"3.0", prefix:"glibc-doc", reference:"2.2.5-11.2")) flag++;
if (deb_check(release:"3.0", prefix:"libc6", reference:"2.2.5-11.2")) flag++;
if (deb_check(release:"3.0", prefix:"libc6-dbg", reference:"2.2.5-11.2")) flag++;
if (deb_check(release:"3.0", prefix:"libc6-dev", reference:"2.2.5-11.2")) flag++;
if (deb_check(release:"3.0", prefix:"libc6-dev-sparc64", reference:"2.2.5-11.2")) flag++;
if (deb_check(release:"3.0", prefix:"libc6-pic", reference:"2.2.5-11.2")) flag++;
if (deb_check(release:"3.0", prefix:"libc6-prof", reference:"2.2.5-11.2")) flag++;
if (deb_check(release:"3.0", prefix:"libc6-sparc64", reference:"2.2.5-11.2")) flag++;
if (deb_check(release:"3.0", prefix:"libc6.1", reference:"2.2.5-11.2")) flag++;
if (deb_check(release:"3.0", prefix:"libc6.1-dbg", reference:"2.2.5-11.2")) flag++;
if (deb_check(release:"3.0", prefix:"libc6.1-dev", reference:"2.2.5-11.2")) flag++;
if (deb_check(release:"3.0", prefix:"libc6.1-pic", reference:"2.2.5-11.2")) flag++;
if (deb_check(release:"3.0", prefix:"libc6.1-prof", reference:"2.2.5-11.2")) flag++;
if (deb_check(release:"3.0", prefix:"locales", reference:"2.2.5-11.2")) flag++;
if (deb_check(release:"3.0", prefix:"nscd", reference:"2.2.5-11.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
