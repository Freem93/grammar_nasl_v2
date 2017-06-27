#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1790. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(38692);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0165", "CVE-2009-0166", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183");
  script_bugtraq_id(34568);
  script_osvdb_id(54465, 54466, 54467, 54468, 54469, 54470, 54471, 54472, 54473, 54476, 54477, 54478, 54479, 54480, 54481, 54482, 54483, 54484, 54485, 54486, 54487, 54488, 54489, 54495, 54496, 54497);
  script_xref(name:"DSA", value:"1790");

  script_name(english:"Debian DSA-1790-1 : xpdf - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been identified in xpdf, a suite of tools
for viewing and converting Portable Document Format (PDF) files.

The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2009-0146
    Multiple buffer overflows in the JBIG2 decoder in Xpdf
    3.02pl2 and earlier, CUPS 1.3.9 and earlier, and other
    products allow remote attackers to cause a denial of
    service (crash) via a crafted PDF file, related to (1)
    JBIG2SymbolDict::setBitmap and (2)
    JBIG2Stream::readSymbolDictSeg.

  - CVE-2009-0147
    Multiple integer overflows in the JBIG2 decoder in Xpdf
    3.02pl2 and earlier, CUPS 1.3.9 and earlier, and other
    products allow remote attackers to cause a denial of
    service (crash) via a crafted PDF file, related to (1)
    JBIG2Stream::readSymbolDictSeg, (2)
    JBIG2Stream::readSymbolDictSeg, and (3)
    JBIG2Stream::readGenericBitmap.

  - CVE-2009-0165
    Integer overflow in the JBIG2 decoder in Xpdf 3.02pl2
    and earlier, as used in Poppler and other products, when
    running on Mac OS X, has unspecified impact, related to
    'g*allocn.'

  - CVE-2009-0166
    The JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS
    1.3.9 and earlier, and other products allows remote
    attackers to cause a denial of service (crash) via a
    crafted PDF file that triggers a free of uninitialized
    memory.

  - CVE-2009-0799
    The JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS
    1.3.9 and earlier, Poppler before 0.10.6, and other
    products allows remote attackers to cause a denial of
    service (crash) via a crafted PDF file that triggers an
    out-of-bounds read.

  - CVE-2009-0800
    Multiple 'input validation flaws' in the JBIG2 decoder
    in Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier,
    Poppler before 0.10.6, and other products allow remote
    attackers to execute arbitrary code via a crafted PDF
    file.

  - CVE-2009-1179
    Integer overflow in the JBIG2 decoder in Xpdf 3.02pl2
    and earlier, CUPS 1.3.9 and earlier, Poppler before
    0.10.6, and other products allows remote attackers to
    execute arbitrary code via a crafted PDF file.

  - CVE-2009-1180
    The JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS
    1.3.9 and earlier, Poppler before 0.10.6, and other
    products allows remote attackers to execute arbitrary
    code via a crafted PDF file that triggers a free of
    invalid data.

  - CVE-2009-1181
    The JBIG2 decoder in Xpdf 3.02pl2 and earlier, CUPS
    1.3.9 and earlier, Poppler before 0.10.6, and other
    products allows remote attackers to cause a denial of
    service (crash) via a crafted PDF file that triggers a
    NULL pointer dereference.

  - CVE-2009-1182
    Multiple buffer overflows in the JBIG2 MMR decoder in
    Xpdf 3.02pl2 and earlier, CUPS 1.3.9 and earlier,
    Poppler before 0.10.6, and other products allow remote
    attackers to execute arbitrary code via a crafted PDF
    file.

  - CVE-2009-1183
    The JBIG2 MMR decoder in Xpdf 3.02pl2 and earlier, CUPS
    1.3.9 and earlier, Poppler before 0.10.6, and other
    products allows remote attackers to cause a denial of
    service (infinite loop and hang) via a crafted PDF file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=524809"
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
    value:"http://www.debian.org/security/2009/dsa-1790"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xpdf packages.

For the old stable distribution (etch), these problems have been fixed
in version 3.01-9.1+etch6.

For the stable distribution (lenny), these problems have been fixed in
version 3.02-1.4+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/06");
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
if (deb_check(release:"4.0", prefix:"xpdf", reference:"3.01-9.1+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"xpdf-common", reference:"3.01-9.1+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"xpdf-reader", reference:"3.01-9.1+etch6")) flag++;
if (deb_check(release:"4.0", prefix:"xpdf-utils", reference:"3.01-9.1+etch6")) flag++;
if (deb_check(release:"5.0", prefix:"xpdf", reference:"3.02-1.4+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"xpdf-common", reference:"3.02-1.4+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"xpdf-reader", reference:"3.02-1.4+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"xpdf-utils", reference:"3.02-1.4+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
