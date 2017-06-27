#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2464. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58978);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/02/16 15:37:38 $");

  script_cve_id("CVE-2012-0467", "CVE-2012-0470", "CVE-2012-0471", "CVE-2012-0477", "CVE-2012-0479");
  script_osvdb_id(81513, 81516, 81517, 81522, 81524);
  script_xref(name:"DSA", value:"2464");

  script_name(english:"Debian DSA-2464-2 : icedove - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Icedove, an unbranded
version of the Thunderbird mail/news client.

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
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=671408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=671410"
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
    value:"https://packages.debian.org/source/squeeze/icedove"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2464"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icedove packages.

For the stable distribution (squeeze), this problem has been fixed in
version 3.0.11-1+squeeze10."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/04");
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
if (deb_check(release:"6.0", prefix:"icedove", reference:"3.0.11-1+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"icedove-dbg", reference:"3.0.11-1+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"icedove-dev", reference:"3.0.11-1+squeeze10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
