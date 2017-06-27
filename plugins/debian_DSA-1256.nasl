#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1256. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24295);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/05/17 23:41:27 $");

  script_cve_id("CVE-2007-0010");
  script_xref(name:"DSA", value:"1256");

  script_name(english:"Debian DSA-1256-1 : gtk+2.0 - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the image loading code in the GTK+ graphical
user interface library performs insufficient error handling when
loading malformed images, which may lead to denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1256"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the GTK packages.

For the stable distribution (sarge) this problem has been fixed in
version 2.6.4-3.2. This update lacks builds for the Motorola 680x0
architecture, which had build problems. Packages will be released once
this problem has been resolved.

For the upcoming stable distribution (etch) this problem has been
fixed in version 2.8.20-5."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gtk+2.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/09");
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
if (deb_check(release:"3.1", prefix:"gtk2-engines-pixbuf", reference:"2.6.4-3.2")) flag++;
if (deb_check(release:"3.1", prefix:"gtk2.0-examples", reference:"2.6.4-3.2")) flag++;
if (deb_check(release:"3.1", prefix:"libgtk2.0-0", reference:"2.6.4-3.2")) flag++;
if (deb_check(release:"3.1", prefix:"libgtk2.0-0-dbg", reference:"2.6.4-3.2")) flag++;
if (deb_check(release:"3.1", prefix:"libgtk2.0-bin", reference:"2.6.4-3.2")) flag++;
if (deb_check(release:"3.1", prefix:"libgtk2.0-common", reference:"2.6.4-3.2")) flag++;
if (deb_check(release:"3.1", prefix:"libgtk2.0-dev", reference:"2.6.4-3.2")) flag++;
if (deb_check(release:"3.1", prefix:"libgtk2.0-doc", reference:"2.6.4-3.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
