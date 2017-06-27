#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1635. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34163);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/05/03 11:20:09 $");

  script_cve_id("CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808");
  script_osvdb_id(46175, 46176, 46177, 46178);
  script_xref(name:"DSA", value:"1635");

  script_name(english:"Debian DSA-1635-1 : freetype - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several local vulnerabilities have been discovered in freetype, a
FreeType 2 font engine, which could allow the execution of arbitrary
code.

The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2008-1806
    An integer overflow allows context-dependent attackers
    to execute arbitrary code via a crafted set of values
    within the Private dictionary table in a Printer Font
    Binary (PFB) file.

  - CVE-2008-1807
    The handling of an invalid 'number of axes' field in the
    PFB file could trigger the freeing of arbitrary memory
    locations, leading to memory corruption.

  - CVE-2008-1808
    Multiple off-by-one errors allowed the execution of
    arbitrary code via malformed tables in PFB files, or
    invalid SHC instructions in TTF files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1635"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the freetype package.

For the stable distribution (etch), these problems have been fixed in
version 2.2.1-5+etch3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freetype");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/11");
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
if (deb_check(release:"4.0", prefix:"freetype2-demos", reference:"2.2.1-5+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libfreetype6", reference:"2.2.1-5+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libfreetype6-dev", reference:"2.2.1-5+etch3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
