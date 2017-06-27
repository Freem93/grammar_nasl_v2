#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1858. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(44723);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2007-1667", "CVE-2007-1797", "CVE-2007-4985", "CVE-2007-4986", "CVE-2007-4987", "CVE-2007-4988", "CVE-2008-1096", "CVE-2008-1097", "CVE-2009-1882");
  script_bugtraq_id(23300, 23347, 25763, 25764, 25765, 25766, 28821, 28822, 35111);
  script_osvdb_id(43213);
  script_xref(name:"DSA", value:"1858");

  script_name(english:"Debian DSA-1858-1 : imagemagick - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the imagemagick image
manipulation programs which can lead to the execution of arbitrary
code, exposure of sensitive information or cause DoS. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2007-1667
    Multiple integer overflows in XInitImage function in
    xwd.c for ImageMagick, allow user-assisted remote
    attackers to cause a denial of service (crash) or obtain
    sensitive information via crafted images with large or
    negative values that trigger a buffer overflow. It only
    affects the oldstable distribution (etch).

  - CVE-2007-1797
    Multiple integer overflows allow remote attackers to
    execute arbitrary code via a crafted DCM image, or the
    colors or comments field in a crafted XWD image. It only
    affects the oldstable distribution (etch).

  - CVE-2007-4985
    A crafted image file can trigger an infinite loop in the
    ReadDCMImage function or in the ReadXCFImage function.
    It only affects the oldstable distribution (etch).

  - CVE-2007-4986
    Multiple integer overflows allow context-dependent
    attackers to execute arbitrary code via a crafted .dcm,
    .dib, .xbm, .xcf, or .xwd image file, which triggers a
    heap-based buffer overflow. It only affects the
    oldstable distribution (etch).

  - CVE-2007-4987
    Off-by-one error allows context-dependent attackers to
    execute arbitrary code via a crafted image file, which
    triggers the writing of a '\0' character to an
    out-of-bounds address. It affects only the oldstable
    distribution (etch).

  - CVE-2007-4988
    A sign extension error allows context-dependent
    attackers to execute arbitrary code via a crafted width
    value in an image file, which triggers an integer
    overflow and a heap-based buffer overflow. It affects
    only the oldstable distribution (etch).

  - CVE-2008-1096
    The load_tile function in the XCF coder allows
    user-assisted remote attackers to cause a denial of
    service or possibly execute arbitrary code via a crafted
    .xcf file that triggers an out-of-bounds heap write. It
    affects only to oldstable (etch).

  - CVE-2008-1097
    Heap-based buffer overflow in the PCX coder allows
    user-assisted remote attackers to cause a denial of
    service or possibly execute arbitrary code via a crafted
    .pcx file that triggers incorrect memory allocation for
    the scanline array, leading to memory corruption. It
    affects only to oldstable (etch).

  - CVE-2009-1882
    Integer overflow allows remote attackers to cause a
    denial of service (crash) and possibly execute arbitrary
    code via a crafted TIFF file, which triggers a buffer
    overflow."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=418057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=412945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=444267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=530838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-1797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4987"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1858"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the imagemagick packages.

For the old stable distribution (etch), these problems have been fixed
in version 7:6.2.4.5.dfsg1-0.15+etch1.

For the stable distribution (lenny), these problems have been fixed in
version 7:6.3.7.9.dfsg2-1~lenny3.

For the upcoming stable distribution (squeeze) and the unstable
distribution (sid), these problems have been fixed in version
7:6.5.1.0-1.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"imagemagick", reference:"7:6.2.4.5.dfsg1-0.15+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmagick++9-dev", reference:"7:6.2.4.5.dfsg1-0.15+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmagick++9c2a", reference:"7:6.2.4.5.dfsg1-0.15+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmagick9", reference:"7:6.2.4.5.dfsg1-0.15+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmagick9-dev", reference:"7:6.2.4.5.dfsg1-0.15+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"perlmagick", reference:"7:6.2.4.5.dfsg1-0.15+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"imagemagick", reference:"7:6.3.7.9.dfsg2-1~lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libmagick++10", reference:"7:6.3.7.9.dfsg2-1~lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libmagick++9-dev", reference:"7:6.3.7.9.dfsg2-1~lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libmagick10", reference:"7:6.3.7.9.dfsg2-1~lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libmagick9-dev", reference:"7:6.3.7.9.dfsg2-1~lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"perlmagick", reference:"7:6.3.7.9.dfsg2-1~lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
