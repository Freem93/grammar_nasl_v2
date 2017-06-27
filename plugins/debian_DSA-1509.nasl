#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1509. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31170);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/03/19 14:28:18 $");

  script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
  script_bugtraq_id(26367);
  script_xref(name:"DSA", value:"1509");

  script_name(english:"Debian DSA-1509-1 : koffice - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in xpdf code that is
embedded in koffice, an integrated office suite for KDE. These flaws
could allow an attacker to execute arbitrary code by inducing the user
to import a specially crafted PDF document. The Common Vulnerabilities
and Exposures project identifies the following problems :

  - CVE-2007-4352
    Array index error in the
    DCTStream::readProgressiveDataUnit method in
    xpdf/Stream.cc in Xpdf 3.02pl1, as used in poppler,
    teTeX, KDE, KOffice, CUPS, and other products, allows
    remote attackers to trigger memory corruption and
    execute arbitrary code via a crafted PDF file.

  - CVE-2007-5392
    Integer overflow in the DCTStream::reset method in
    xpdf/Stream.cc in Xpdf 3.02p11 allows remote attackers
    to execute arbitrary code via a crafted PDF file,
    resulting in a heap-based buffer overflow.

  - CVE-2007-5393
    Heap-based buffer overflow in the
    CCITTFaxStream::lookChar method in xpdf/Stream.cc in
    Xpdf 3.02p11 allows remote attackers to execute
    arbitrary code via a PDF file that contains a crafted
    CCITTFaxDecode filter.

Updates for the old stable distribution (sarge) will be made available
as soon as possible."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5393"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1509"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the koffice package.

For the stable distribution (etch), these problems have been fixed in
version 1:1.6.1-2etch2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:koffice");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"karbon", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kchart", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kexi", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kformula", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kivio", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kivio-data", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"koffice", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"koffice-data", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"koffice-dbg", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"koffice-dev", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"koffice-doc", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"koffice-doc-html", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"koffice-libs", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"koshell", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kplato", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kpresenter", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kpresenter-data", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"krita", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"krita-data", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kspread", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kthesaurus", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kugar", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kword", reference:"1:1.6.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"kword-data", reference:"1:1.6.1-2etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
