#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1903. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(44768);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2007-1667", "CVE-2007-1797", "CVE-2007-4985", "CVE-2007-4986", "CVE-2007-4988", "CVE-2008-1096", "CVE-2008-3134", "CVE-2008-6070", "CVE-2008-6071", "CVE-2008-6072", "CVE-2008-6621", "CVE-2009-1882");
  script_osvdb_id(34107, 34108, 34688, 34689, 41325, 41327, 41328, 41329, 41330, 41331, 41332, 43212, 46254, 46255, 46256, 46257, 46258, 46632, 46633, 54729);
  script_xref(name:"DSA", value:"1903");

  script_name(english:"Debian DSA-1903-1 : graphicsmagick - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in graphicsmagick, a
collection of image processing tool, which can lead to the execution
of arbitrary code, exposure of sensitive information or cause DoS. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2007-1667
    Multiple integer overflows in XInitImage function in
    xwd.c for GraphicsMagick, allow user-assisted remote
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
    affects only oldstable (etch).

  - CVE-2008-3134
    Multiple vulnerabilities in GraphicsMagick before 1.2.4
    allow remote attackers to cause a denial of service
    (crash, infinite loop, or memory consumption) via
    vectors in the AVI, AVS, DCM, EPT, FITS, MTV, PALM, RLA,
    and TGA decoder readers; and the GetImageCharacteristics
    function in magick/image.c, as reachable from a crafted
    PNG, JPEG, BMP, or TIFF file.

  - CVE-2008-6070
    Multiple heap-based buffer underflows in the
    ReadPALMImage function in coders/palm.c in
    GraphicsMagick before 1.2.3 allow remote attackers to
    cause a denial of service (crash) or possibly execute
    arbitrary code via a crafted PALM image.

  - CVE-2008-6071
    Heap-based buffer overflow in the DecodeImage function
    in coders/pict.c in GraphicsMagick before 1.1.14, and
    1.2.x before 1.2.3, allows remote attackers to cause a
    denial of service (crash) or possibly execute arbitrary
    code via a crafted PICT image.

  - CVE-2008-6072
    Multiple vulnerabilities in GraphicsMagick allow remote
    attackers to cause a denial of service (crash) via
    vectors in XCF and CINEON images.

  - CVE-2008-6621
    Vulnerability in GraphicsMagick allows remote attackers
    to cause a denial of service (crash) via vectors in DPX
    images.

  - CVE-2009-1882
    Integer overflow allows remote attackers to cause a
    denial of service (crash) and possibly execute arbitrary
    code via a crafted TIFF file, which triggers a buffer
    overflow."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=414370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=417862"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=444266"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=491439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=530946"
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
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3134"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-6070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-6071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-6072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-6621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1903"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the graphicsmagick packages.

For the oldstable distribution (etch), these problems have been fixed
in version 1.1.7-13+etch1.

For the stable distribution (lenny), these problems have been fixed in
version 1.1.11-3.2+lenny1.

For the upcoming stable distribution (squeeze) and the unstable
distribution (sid), these problems have been fixed in version
1.3.5-5.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/31");
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
if (deb_check(release:"4.0", prefix:"graphicsmagick", reference:"1.1.7-13+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"graphicsmagick-dbg", reference:"1.1.7-13+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"graphicsmagick-imagemagick-compat", reference:"1.1.7-13+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"graphicsmagick-libmagick-dev-compat", reference:"1.1.7-13+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgraphics-magick-perl", reference:"1.1.7-13+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgraphicsmagick++1", reference:"1.1.7-13+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgraphicsmagick++1-dev", reference:"1.1.7-13+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgraphicsmagick1", reference:"1.1.7-13+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgraphicsmagick1-dev", reference:"1.1.7-13+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"graphicsmagick", reference:"1.1.11-3.2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"graphicsmagick-dbg", reference:"1.1.11-3.2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"graphicsmagick-imagemagick-compat", reference:"1.1.11-3.2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"graphicsmagick-libmagick-dev-compat", reference:"1.1.11-3.2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libgraphics-magick-perl", reference:"1.1.11-3.2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libgraphicsmagick++1", reference:"1.1.11-3.2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libgraphicsmagick++1-dev", reference:"1.1.11-3.2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libgraphicsmagick1", reference:"1.1.11-3.2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libgraphicsmagick1-dev", reference:"1.1.11-3.2+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
