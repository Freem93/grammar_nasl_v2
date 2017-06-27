#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1318. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25584);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/08/20 15:05:35 $");

  script_cve_id("CVE-2005-2370", "CVE-2005-2448", "CVE-2007-1663", "CVE-2007-1664", "CVE-2007-1665");
  script_osvdb_id(45377, 45378, 45379);
  script_xref(name:"DSA", value:"1318");

  script_name(english:"Debian DSA-1318-1 : ekg - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in ekg, a console
Gadu Gadu client. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2005-2370
    It was discovered that memory alignment errors may allow
    remote attackers to cause a denial of service on certain
    architectures such as sparc. This only affects Debian
    Sarge.

  - CVE-2005-2448
    It was discovered that several endianess errors may
    allow remote attackers to cause a denial of service.
    This only affects Debian Sarge.

  - CVE-2007-1663
    It was discovered that a memory leak in handling image
    messages may lead to denial of service. This only
    affects Debian Etch.

  - CVE-2007-1664
    It was discovered that a NULL pointer deference in the
    token OCR code may lead to denial of service. This only
    affects Debian Etch.

  - CVE-2007-1665
    It was discovered that a memory leak in the token OCR
    code may lead to denial of service. This only affects
    Debian Etch."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-2370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-2448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1318"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ekg packages.

For the oldstable distribution (sarge) these problems have been fixed
in version 1.5+20050411-7. This updates lacks updated packages for the
m68k architecture. They will be provided later.

For the stable distribution (etch) these problems have been fixed in
version 1:1.7~rc2-1etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ekg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"ekg", reference:"1.5+20050411-7")) flag++;
if (deb_check(release:"3.1", prefix:"libgadu-dev", reference:"1.5+20050411-7")) flag++;
if (deb_check(release:"3.1", prefix:"libgadu3", reference:"1.5+20050411-7")) flag++;
if (deb_check(release:"4.0", prefix:"ekg", reference:"1:1.7~rc2-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgadu-dev", reference:"1:1.7~rc2-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgadu3", reference:"1:1.7~rc2-1etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
