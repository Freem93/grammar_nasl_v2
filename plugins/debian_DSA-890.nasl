#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-890. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22756);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/08/20 15:05:35 $");

  script_cve_id("CVE-2005-2974", "CVE-2005-3350");
  script_osvdb_id(20470, 20471);
  script_xref(name:"DSA", value:"890");

  script_name(english:"Debian DSA-890-1 : libungif4 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chris Evans discovered several security related problems in libungif4,
a shared library for GIF images. The Common Vulnerabilities and
Exposures project identifies the following vulnerabilities :

  - CVE-2005-2974
    NULL pointer dereference, that could cause a denial of
    service.

  - CVE-2005-3350
    Out of bounds memory access that could cause a denial of
    service or the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=337972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-890"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libungif4 packages.

For the old stable distribution (woody) these problems have been fixed
in version 4.1.0b1-2woody1.

For the stable distribution (sarge) these problems have been fixed in
version 4.1.3-2sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libungif4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"libungif-bin", reference:"4.1.0b1-2woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libungif4-dev", reference:"4.1.0b1-2woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libungif4g", reference:"4.1.0b1-2woody1")) flag++;
if (deb_check(release:"3.1", prefix:"libungif-bin", reference:"4.1.3-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libungif4-dev", reference:"4.1.3-2sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libungif4g", reference:"4.1.3-2sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
