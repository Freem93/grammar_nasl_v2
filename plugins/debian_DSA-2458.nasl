#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2458. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58855);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/02/16 15:37:38 $");

  script_cve_id("CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0458", "CVE-2012-0461", "CVE-2012-0467", "CVE-2012-0470", "CVE-2012-0471", "CVE-2012-0477", "CVE-2012-0479");
  script_bugtraq_id(52458, 52460, 52461, 52464, 53219, 53223, 53224, 53225, 53229);
  script_osvdb_id(80011, 80012, 80015, 80018, 81513, 81516, 81517, 81522, 81524);
  script_xref(name:"DSA", value:"2458");

  script_name(english:"Debian DSA-2458-2 : iceape - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in the Iceape internet suite,
an unbranded version of SeaMonkey :

  - CVE-2012-0455
    Soroush Dalili discovered that a cross-site scripting
    countermeasure related to JavaScript URLs could be
    bypassed.

  - CVE-2012-0456
    Atte Kettunen discovered an out of bounds read in the
    SVG Filters, resulting in memory disclosure.

  - CVE-2012-0458
    Mariusz Mlynski discovered that privileges could be
    escalated through a JavaScript URL as the home page.

  - CVE-2012-0461
    Bob Clary discovered memory corruption bugs, which may
    lead to the execution of arbitrary code.

  - CVE-2012-0467
    Bob Clary, Christian Holler, Brian Hackett, Bobby
    Holley, Gary Kwong, Hilary Hall, Honza Bambas, Jesse
    Ruderman, Julian Seward, and Olli Pettay discovered
    memory corruption bugs, which may lead to the execution
    of arbitrary code.

  - CVE-2012-0470
    Atte Kettunen discovered that a memory corruption bug in
    gfxImageSurface may lead to the execution of arbitrary
    code.

  - CVE-2012-0471
    Anne van Kesteren discovered that incorrect multibyte
    character encoding may lead to cross-site scripting.

  - CVE-2012-0477
    Masato Kinugawa discovered that incorrect encoding of
    Korean and Chinese character sets may lead to cross-site
    scripting.

  - CVE-2012-0479
    Jeroen van der Gun discovered a spoofing vulnerability
    in the presentation of Atom and RSS feeds over HTTPS."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0479"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/iceape"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2458"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the iceape packages.

For the stable distribution (squeeze), this problem has been fixed in
version 2.0.11-12"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceape");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"iceape", reference:"2.0.11-12")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-browser", reference:"2.0.11-12")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-chatzilla", reference:"2.0.11-12")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-dbg", reference:"2.0.11-12")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-dev", reference:"2.0.11-12")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-mailnews", reference:"2.0.11-12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
