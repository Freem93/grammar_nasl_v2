#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-140. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14977);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/17 23:45:44 $");

  script_cve_id("CVE-2002-0660", "CVE-2002-0728");
  script_xref(name:"DSA", value:"140");

  script_name(english:"Debian DSA-140-2 : libpng - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Developers of the PNG library have fixed a buffer overflow in the
progressive reader when the PNG datastream contains more IDAT data
than indicated by the IHDR chunk. Such deliberately malformed
datastreams would crash applications which could potentially allow an
attacker to execute malicious code. Programs such as Galeon, Konqueror
and various others make use of these libraries.

In addition to that, the packages below fix another potential buffer
overflow. The PNG libraries implement a safety margin which is also
included in a newer upstream release. Thanks to Glenn Randers-Pehrson
for informing us.

To find out which packages depend on this library, you may want to
execute the following commands :

    apt-cache showpkg libpng2 apt-cache showpkg libpng3"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-140"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libpng packages immediately and restart programs and
daemons that link to these libraries and read external data, such as
web browsers.

This problem has been fixed in version 1.0.12-3.woody.2 of libpng and
version 1.2.1-1.1.woody.2 of libpng3 for the current stable
distribution (woody) and in version 1.0.12-4 of libpng and version
1.2.1-2 of libpng3 for the unstable distribution (sid). The potato
release of Debian does not seem to be vulnerable."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpng3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/08/05");
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
if (deb_check(release:"3.0", prefix:"libpng-dev", reference:"1.2.1-1.1.woody.2")) flag++;
if (deb_check(release:"3.0", prefix:"libpng2", reference:"1.0.12-3.woody.2")) flag++;
if (deb_check(release:"3.0", prefix:"libpng2-dev", reference:"1.0.12-3.woody.2")) flag++;
if (deb_check(release:"3.0", prefix:"libpng3", reference:"1.2.1-1.1.woody.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
