#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1793. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38703);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0165", "CVE-2009-0166", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183");
  script_bugtraq_id(34568);
  script_xref(name:"DSA", value:"1793");

  script_name(english:"Debian DSA-1793-1 : kdegraphics - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"kpdf, a Portable Document Format (PDF) viewer for KDE, is based on the
xpdf program and thus suffers from similar flaws to those described in
DSA-1790.

The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2009-0146
    Multiple buffer overflows in the JBIG2 decoder in kpdf
    allow remote attackers to cause a denial of service
    (crash) via a crafted PDF file, related to (1)
    JBIG2SymbolDict::setBitmap and (2)
    JBIG2Stream::readSymbolDictSeg.

  - CVE-2009-0147
    Multiple integer overflows in the JBIG2 decoder in kpdf
    allow remote attackers to cause a denial of service
    (crash) via a crafted PDF file, related to (1)
    JBIG2Stream::readSymbolDictSeg, (2)
    JBIG2Stream::readSymbolDictSeg, and (3)
    JBIG2Stream::readGenericBitmap.

  - CVE-2009-0165
    Integer overflow in the JBIG2 decoder in kpdf has
    unspecified impact related to 'g*allocn.'

  - CVE-2009-0166
    The JBIG2 decoder in kpdf allows remote attackers to
    cause a denial of service (crash) via a crafted PDF file
    that triggers a free of uninitialized memory.

  - CVE-2009-0799
    The JBIG2 decoder in kpdf allows remote attackers to
    cause a denial of service (crash) via a crafted PDF file
    that triggers an out-of-bounds read.

  - CVE-2009-0800
    Multiple 'input validation flaws' in the JBIG2 decoder
    in kpdf allow remote attackers to execute arbitrary code
    via a crafted PDF file.

  - CVE-2009-1179
    Integer overflow in the JBIG2 decoder in kpdf allows
    remote attackers to execute arbitrary code via a crafted
    PDF file.

  - CVE-2009-1180
    The JBIG2 decoder in kpdf allows remote attackers to
    execute arbitrary code via a crafted PDF file that
    triggers a free of invalid data.

  - CVE-2009-1181
    The JBIG2 decoder in kpdf allows remote attackers to
    cause a denial of service (crash) via a crafted PDF file
    that triggers a NULL pointer dereference.

  - CVE-2009-1182
    Multiple buffer overflows in the JBIG2 MMR decoder in
    kpdf allow remote attackers to execute arbitrary code
    via a crafted PDF file.

  - CVE-2009-1183
    The JBIG2 MMR decoder in kpdf allows remote attackers to
    cause a denial of service (infinite loop and hang) via a
    crafted PDF file.

The old stable distribution (etch), these problems have been fixed in
version 3.5.5-3etch3."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=524810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0146"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0147"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1793"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kdegraphics packages.

For the stable distribution (lenny), these problems have been fixed in
version 3.5.9-3+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdegraphics");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/08");
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
if (deb_check(release:"4.0", prefix:"kamera", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kcoloredit", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kdegraphics", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kdegraphics-dbg", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kdegraphics-dev", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kdegraphics-doc-html", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kdegraphics-kfile-plugins", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kdvi", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kfax", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kfaxview", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kgamma", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kghostview", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kiconedit", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kmrml", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kolourpaint", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kooka", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kpdf", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kpovmodeler", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kruler", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ksnapshot", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"ksvg", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kuickshow", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kview", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"kviewshell", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libkscan-dev", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libkscan1", reference:"3.5.5-3etch3")) flag++;
if (deb_check(release:"5.0", prefix:"kamera", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kcoloredit", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kdegraphics", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kdegraphics-dbg", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kdegraphics-dev", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kdegraphics-doc-html", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kdegraphics-kfile-plugins", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kdvi", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kfax", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kfaxview", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kgamma", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kghostview", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kiconedit", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kmrml", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kolourpaint", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kooka", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kpdf", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kpovmodeler", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kruler", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ksnapshot", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"ksvg", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kuickshow", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kview", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"kviewshell", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libkscan-dev", reference:"3.5.9-3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libkscan1", reference:"3.5.9-3+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
