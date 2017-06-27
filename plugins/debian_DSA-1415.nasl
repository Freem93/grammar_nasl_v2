#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1415. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28338);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/05/17 23:45:44 $");

  script_cve_id("CVE-2007-5137", "CVE-2007-5378", "CVE-2008-0553");
  script_osvdb_id(41264);
  script_xref(name:"DSA", value:"1415");

  script_name(english:"Debian DSA-1415-1 : tk8.4 - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Tk, a cross-platform graphical toolkit for Tcl,
performs insufficient input validation in the code used to load GIF
images, which may lead to the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1415"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the tk8.4 packages. Updated packages for sparc will be
provided later.

For the old stable distribution (sarge), this problem has been fixed
in version 8.4.9-1sarge1.

For the stable distribution (etch), this problem has been fixed in
version 8.4.12-1etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tk8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/29");
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
if (deb_check(release:"3.1", prefix:"tk8.4", reference:"8.4.9-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"tk8.4-dev", reference:"8.4.9-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"tk8.4-doc", reference:"8.4.9-1sarge1")) flag++;
if (deb_check(release:"4.0", prefix:"tk8.4", reference:"8.4.12-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"tk8.4-dev", reference:"8.4.12-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"tk8.4-doc", reference:"8.4.12-1etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
