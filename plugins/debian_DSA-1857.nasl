#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1857. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44722);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/05/17 23:54:22 $");

  script_cve_id("CVE-2009-2660");
  script_osvdb_id(56793, 56794);
  script_xref(name:"DSA", value:"1857");

  script_name(english:"Debian DSA-1857-1 : camlimages - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tielei Wang discovered that CamlImages, an open source image
processing library, suffers from several integer overflows which may
lead to a potentially exploitable heap overflow and result in
arbitrary code execution. This advisory addresses issues with the
reading of JPEG and GIF Images, while DSA 1832-1addressed the issue
with PNG images."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=540146"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1857"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the camlimages package.

For the oldstable distribution (etch), this problem has been fixed in
version 2.20-8+etch2.

For the stable distribution (lenny), this problem has been fixed in
version 1:2.2.0-4+lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:camlimages");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
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
if (deb_check(release:"4.0", prefix:"libcamlimages-ocaml", reference:"2.20-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libcamlimages-ocaml-dev", reference:"2.20-8+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libcamlimages-ocaml-doc", reference:"2.20-8+etch2")) flag++;
if (deb_check(release:"5.0", prefix:"libcamlimages-ocaml", reference:"1:2.2.0-4+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libcamlimages-ocaml-dev", reference:"1:2.2.0-4+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libcamlimages-ocaml-doc", reference:"1:2.2.0-4+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
