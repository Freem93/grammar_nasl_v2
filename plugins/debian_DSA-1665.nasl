#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1665. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34757);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/05/17 23:49:55 $");

  script_cve_id("CVE-2008-5030");
  script_xref(name:"DSA", value:"1665");

  script_name(english:"Debian DSA-1665-1 : libcdaudio - heap overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that a heap overflow in the CDDB retrieval code of
libcdaudio, a library for controlling a CD-ROM when playing audio CDs,
may result in the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1665"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libcdaudio packages.

For the stable distribution (etch), this problem has been fixed in
version 0.99.12p2-2+etch1. A package for hppa will be provided later.

For the upcoming stable distribution (lenny) and the unstable
distribution (sid), this problem has been fixed in version
0.99.12p2-7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcdaudio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libcdaudio-dev", reference:"0.99.12p2-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libcdaudio1", reference:"0.99.12p2-2+etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
