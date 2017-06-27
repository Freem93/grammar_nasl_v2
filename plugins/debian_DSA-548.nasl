#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-548. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15385);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2013/05/18 00:11:36 $");

  script_cve_id("CVE-2004-0817");
  script_osvdb_id(9435, 9781);
  script_xref(name:"DSA", value:"548");

  script_name(english:"Debian DSA-548-2 : imlib - unsanitised input");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Marcus Meissner discovered a heap overflow error in imlib, an imaging
library for X and X11, that could be abused by an attacker to execute
arbitrary code on the victim's machine. The updated packages we have
provided in DSA 548-1 did not seem to be sufficient, which should be
fixed by this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-548"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the imlib1 packages.

For the old stable distribution (woody) this problem has been fixed in
version 1.9.14-2woody3.

For the stable distribution (sarge) this problem has been fixed in
version 1.9.14-16.2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/25");
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
if (deb_check(release:"3.0", prefix:"gdk-imlib-dev", reference:"1.9.14-2woody3")) flag++;
if (deb_check(release:"3.0", prefix:"gdk-imlib1", reference:"1.9.14-2woody3")) flag++;
if (deb_check(release:"3.0", prefix:"imlib-base", reference:"1.9.14-2woody3")) flag++;
if (deb_check(release:"3.0", prefix:"imlib-dev", reference:"1.9.14-2woody3")) flag++;
if (deb_check(release:"3.0", prefix:"imlib-progs", reference:"1.9.14-2woody3")) flag++;
if (deb_check(release:"3.0", prefix:"imlib1", reference:"1.9.14-2woody3")) flag++;
if (deb_check(release:"3.1", prefix:"imlib", reference:"1.9.14-16.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
