#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2188. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(52620);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/02/16 15:31:55 $");

  script_cve_id("CVE-2010-0474", "CVE-2010-1783", "CVE-2010-2901", "CVE-2010-4040", "CVE-2010-4199", "CVE-2010-4492", "CVE-2010-4493", "CVE-2010-4577", "CVE-2010-4578", "CVE-2011-0482", "CVE-2011-0778");
  script_bugtraq_id(42035, 45722, 45788, 46144);
  script_xref(name:"DSA", value:"2188");

  script_name(english:"Debian DSA-2188-1 : webkit - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in WebKit, a Web content
engine library for GTK+. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2010-1783
    WebKit does not properly handle dynamic modification of
    a text node, which allows remote attackers to execute
    arbitrary code or cause a denial of service (memory
    corruption and application crash) via a crafted HTML
    document.

  - CVE-2010-2901
    The rendering implementation in WebKit allows remote
    attackers to cause a denial of service (memory
    corruption) or possibly have unspecified other impact
    via unknown vectors.

  - CVE-2010-4199
    WebKit does not properly perform a cast of an
    unspecified variable during processing of an SVG <use>
    element, which allows remote attackers to cause a denial
    of service or possibly have unspecified other impact via
    a crafted SVG document.

  - CVE-2010-4040
    WebKit does not properly handle animated GIF images,
    which allows remote attackers to cause a denial of
    service (memory corruption) or possibly have unspecified
    other impact via a crafted image.

  - CVE-2010-4492
    Use-after-free vulnerability in WebKit allows remote
    attackers to cause a denial of service or possibly have
    unspecified other impact via vectors involving SVG
    animations.

  - CVE-2010-4493
    Use-after-free vulnerability in WebKit allows remote
    attackers to cause a denial of service via vectors
    related to the handling of mouse dragging events.

  - CVE-2010-4577
    The CSSParser::parseFontFaceSrc function in
    WebCore/css/CSSParser.cpp in WebKit does not properly
    parse Cascading Style Sheets (CSS) token sequences,
    which allows remote attackers to cause a denial of
    service (out-of-bounds read) via a crafted local font,
    related to 'Type Confusion'.

  - CVE-2010-4578
    WebKit does not properly perform cursor handling, which
    allows remote attackers to cause a denial of service or
    possibly have unspecified other impact via unknown
    vectors that lead to 'stale pointers'.

  - CVE-2011-0482
    WebKit does not properly perform a cast of an
    unspecified variable during handling of anchors, which
    allows remote attackers to cause a denial of service or
    possibly have unspecified other impact via a crafted
    HTML document.

  - CVE-2011-0778
    WebKit does not properly restrict drag and drop
    operations, which might allow remote attackers to bypass
    the Same Origin Policy via unspecified vectors."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/webkit"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2188"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the webkit packages.

For the stable distribution (squeeze), these problems have been fixed
in version 1.2.7-0+squeeze1.

Security support for WebKit has been discontinued for the oldstable
distribution (lenny). The current version in oldstable is not
supported by upstream anymore and is affected by several security
issues. Backporting fixes for these and any future issues has become
unfeasible and therefore we need to drop our security support for the
version in oldstable."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:webkit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"gir1.0-webkit-1.0", reference:"1.2.7-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libwebkit-1.0-2", reference:"1.2.7-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libwebkit-1.0-2-dbg", reference:"1.2.7-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libwebkit-1.0-common", reference:"1.2.7-0+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libwebkit-dev", reference:"1.2.7-0+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
