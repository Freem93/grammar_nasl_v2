#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1455. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29902);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/05/03 11:14:59 $");

  script_cve_id("CVE-2007-3641", "CVE-2007-3644", "CVE-2007-3645");
  script_osvdb_id(38092, 38093, 38094);
  script_xref(name:"DSA", value:"1455");

  script_name(english:"Debian DSA-1455-1 : libarchive - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several local/remote vulnerabilities have been discovered in
libarchive1, a single library to read/write tar, cpio, pax, zip,
iso9660 archives. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2007-3641
    It was discovered that libarchive1 would miscompute the
    length of a buffer resulting in a buffer overflow if yet
    another type of corruption occurred in a pax extension
    header.

  - CVE-2007-3644
    It was discovered that if an archive prematurely ended
    within a pax extension header the libarchive1 library
    could enter an infinite loop.

  - CVE-2007-3645
    If an archive prematurely ended within a tar header,
    immediately following a pax extension header,
    libarchive1 could dereference a NULL pointer."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=432924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1455"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libarchive package.

The old stable distribution (sarge), does not contain this package.

For the stable distribution (etch), these problems have been fixed in
version 1.2.53-2etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libarchive1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"bsdtar", reference:"1.2.53-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libarchive-dev", reference:"1.2.53-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libarchive1", reference:"1.2.53-2etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
