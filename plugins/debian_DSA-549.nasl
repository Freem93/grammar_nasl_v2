#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-549. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15386);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/18 00:11:36 $");

  script_cve_id("CVE-2004-0782", "CVE-2004-0783", "CVE-2004-0788");
  script_xref(name:"CERT", value:"369358");
  script_xref(name:"CERT", value:"577654");
  script_xref(name:"CERT", value:"729894");
  script_xref(name:"DSA", value:"549");

  script_name(english:"Debian DSA-549-1 : gtk+ - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chris Evans discovered several problems in gdk-pixbuf, the GdkPixBuf
library used in Gtk. It is possible for an attacker to execute
arbitrary code on the victims machine. Gdk-pixbuf for Gtk+1.2 is an
external package. For Gtk+2.0 it's part of the main gtk package.

The Common Vulnerabilities and Exposures Project identifies the
following vulnerabilities :

  - CAN-2004-0782
    Heap-based overflow in pixbuf_create_from_xpm.

  - CAN-2004-0783

    Stack-based overflow in xpm_extract_color.

  - CAN-2004-0788

    Integer overflow in the ico loader."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-549"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Gtk packages.

For the stable distribution (woody) these problems have been fixed in
version 2.0.2-5woody2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gtk+2.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/17");
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
if (deb_check(release:"3.0", prefix:"gtk2.0-examples", reference:"2.0.2-5woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libgtk-common", reference:"2.0.2-5woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libgtk2.0-0", reference:"2.0.2-5woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libgtk2.0-common", reference:"2.0.2-5woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libgtk2.0-dbg", reference:"2.0.2-5woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libgtk2.0-dev", reference:"2.0.2-5woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libgtk2.0-doc", reference:"2.0.2-5woody2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
