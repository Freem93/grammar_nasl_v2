#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1830. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(44695);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2009-0040", "CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0652", "CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0776", "CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1307", "CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1836", "CVE-2009-1838", "CVE-2009-1841");
  script_bugtraq_id(33598, 33990, 35370, 35371, 35373, 35380, 35383);
  script_xref(name:"DSA", value:"1830");

  script_name(english:"Debian DSA-1830-1 : icedove - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the Icedove
mail client, an unbranded version of the Thunderbird mail client. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2009-0040
    The execution of arbitrary code might be possible via a
    crafted PNG file that triggers a free of an
    uninitialized pointer in (1) the png_read_png function,
    (2) pCAL chunk handling, or (3) setup of 16-bit gamma
    tables. (MFSA 2009-10)

  - CVE-2009-0352
    It is possible to execute arbitrary code via vectors
    related to the layout engine. (MFSA 2009-01)

  - CVE-2009-0353
    It is possible to execute arbitrary code via vectors
    related to the JavaScript engine. (MFSA 2009-01)

  - CVE-2009-0652
    Bjoern Hoehrmann and Moxie Marlinspike discovered a
    possible spoofing attack via Unicode box drawing
    characters in internationalized domain names. (MFSA
    2009-15)

  - CVE-2009-0771
    Memory corruption and assertion failures have been
    discovered in the layout engine, leading to the possible
    execution of arbitrary code. (MFSA 2009-07)

  - CVE-2009-0772
    The layout engine allows the execution of arbitrary code
    in vectors related to nsCSSStyleSheet::GetOwnerNode,
    events, and garbage collection. (MFSA 2009-07)

  - CVE-2009-0773
    The JavaScript engine is prone to the execution of
    arbitrary code via several vectors. (MFSA 2009-07)

  - CVE-2009-0774
    The layout engine allows the execution of arbitrary code
    via vectors related to gczeal. (MFSA 2009-07)

  - CVE-2009-0776
    Georgi Guninski discovered that it is possible to obtain
    xml data via an issue related to the nsIRDFService.
    (MFSA 2009-09)

  - CVE-2009-1302
    The browser engine is prone to a possible memory
    corruption via several vectors. (MFSA 2009-14)

  - CVE-2009-1303
    The browser engine is prone to a possible memory
    corruption via the nsSVGElement::BindToTree function.
    (MFSA 2009-14)

  - CVE-2009-1307
    Gregory Fleischer discovered that it is possible to
    bypass the Same Origin Policy when opening a Flash file
    via the view-source: scheme. (MFSA 2009-17)

  - CVE-2009-1832
    The possible arbitrary execution of code was discovered
    via vectors involving 'double frame construction.' (MFSA
    2009-24)

  - CVE-2009-1392
    Several issues were discovered in the browser engine as
    used by icedove, which could lead to the possible
    execution of arbitrary code. (MFSA 2009-24)

  - CVE-2009-1836
    Shuo Chen, Ziqing Mao, Yi-Min Wang and Ming Zhang
    reported a potential man-in-the-middle attack, when
    using a proxy due to insufficient checks on a certain
    proxy response. (MFSA 2009-27)

  - CVE-2009-1838
    moz_bug_r_a4 discovered that it is possible to execute
    arbitrary JavaScript with chrome privileges due to an
    error in the garbage collection implementation. (MFSA
    2009-29)

  - CVE-2009-1841
    moz_bug_r_a4 reported that it is possible for scripts
    from page content to run with elevated privileges and
    thus potentially executing arbitrary code with the
    object's chrome privileges. (MFSA 2009-32)

  - No CVE id yet

    Bernd Jendrissek discovered a potentially exploitable
    crash when viewing a multipart/alternative mail message
    with a text/enhanced part. (MFSA 2009-33)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1830"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icedove packages.

For the stable distribution (lenny), these problems have been fixed in
version 2.0.0.22-0lenny1.

As indicated in the Etch release notes, security support for the
Mozilla products in the oldstable distribution needed to be stopped
before the end of the regular Etch security maintenance life cycle.
You are strongly encouraged to upgrade to stable or switch to a still
supported mail client.

For the testing (squeeze) distribution these problems will be fixed
soon."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 20, 94, 200, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/12");
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
if (deb_check(release:"5.0", prefix:"icedove", reference:"2.0.0.22-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"icedove-dbg", reference:"2.0.0.22-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"icedove-dev", reference:"2.0.0.22-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"icedove-gnome-support", reference:"2.0.0.22-0lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
