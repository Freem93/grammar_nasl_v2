#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1351. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25859);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/05/17 23:41:28 $");

  script_cve_id("CVE-2007-2893");
  script_osvdb_id(36799);
  script_xref(name:"DSA", value:"1351");

  script_name(english:"Debian DSA-1351-1 : bochs - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tavis Ormandy discovered that bochs, a highly portable IA-32 PC
emulator, is vulnerable to a buffer overflow in the emulated NE2000
network device driver, which may lead to privilege escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1351"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bochs packages.

For the oldstable distribution (sarge) this problem has been fixed in
version 2.1.1+20041109-3sarge1.

For the stable distribution (etch) this problem has been fixed in
version 2.3-2etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bochs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"bochs", reference:"2.1.1+20041109-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"bochs-doc", reference:"2.1.1+20041109-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"bochs-sdl", reference:"2.1.1+20041109-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"bochs-svga", reference:"2.1.1+20041109-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"bochs-term", reference:"2.1.1+20041109-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"bochs-wx", reference:"2.1.1+20041109-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"bochs-x", reference:"2.1.1+20041109-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"bochsbios", reference:"2.1.1+20041109-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"bximage", reference:"2.1.1+20041109-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"sb16ctrl-bochs", reference:"2.1.1+20041109-3sarge1")) flag++;
if (deb_check(release:"4.0", prefix:"bochs", reference:"2.3-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"bochs-doc", reference:"2.3-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"bochs-sdl", reference:"2.3-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"bochs-svga", reference:"2.3-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"bochs-term", reference:"2.3-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"bochs-wx", reference:"2.3-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"bochs-x", reference:"2.3-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"bochsbios", reference:"2.3-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"bximage", reference:"2.3-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"sb16ctrl-bochs", reference:"2.3-2etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
