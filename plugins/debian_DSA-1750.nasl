#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1750. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35988);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2007-2445", "CVE-2007-5269", "CVE-2008-1382", "CVE-2008-5907", "CVE-2008-6218", "CVE-2009-0040");
  script_bugtraq_id(25956, 28276, 28770, 31920, 33827, 33990);
  script_osvdb_id(53314);
  script_xref(name:"DSA", value:"1750");

  script_name(english:"Debian DSA-1750-1 : libpng - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in libpng, a library for
reading and writing PNG files. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2007-2445
    The png_handle_tRNS function allows attackers to cause a
    denial of service (application crash) via a grayscale
    PNG image with a bad tRNS chunk CRC value.

  - CVE-2007-5269
    Certain chunk handlers allow attackers to cause a denial
    of service (crash) via crafted pCAL, sCAL, tEXt, iTXt,
    and ztXT chunking in PNG images, which trigger
    out-of-bounds read operations.

  - CVE-2008-1382
    libpng allows context-dependent attackers to cause a
    denial of service (crash) and possibly execute arbitrary
    code via a PNG file with zero length 'unknown' chunks,
    which trigger an access of uninitialized memory.

  - CVE-2008-5907
    The png_check_keyword might allow context-dependent
    attackers to set the value of an arbitrary memory
    location to zero via vectors involving creation of
    crafted PNG files with keywords.

  - CVE-2008-6218
    A memory leak in the png_handle_tEXt function allows
    context-dependent attackers to cause a denial of service
    (memory exhaustion) via a crafted PNG file.

  - CVE-2009-0040
    libpng allows context-dependent attackers to cause a
    denial of service (application crash) or possibly
    execute arbitrary code via a crafted PNG file that
    triggers a free of an uninitialized pointer in (1) the
    png_read_png function, (2) pCAL chunk handling, or (3)
    setup of 16-bit gamma tables."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=446308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=476669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=516256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=512665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-6218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1750"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libpng packages.

For the old stable distribution (etch), these problems have been fixed
in version 1.2.15~beta5-1+etch2.

For the stable distribution (lenny), these problems have been fixed in
version 1.2.27-2+lenny2. (Only CVE-2008-5907, CVE-2008-5907 and
CVE-2009-0040 affect the stable distribution.)"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 94, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpng");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libpng12-0", reference:"1.2.15~beta5-1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libpng12-dev", reference:"1.2.15~beta5-1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libpng3", reference:"1.2.15~beta5-1+etch2")) flag++;
if (deb_check(release:"5.0", prefix:"libpng12-0", reference:"1.2.27-2+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libpng12-dev", reference:"1.2.27-2+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libpng3", reference:"1.2.27-2+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
