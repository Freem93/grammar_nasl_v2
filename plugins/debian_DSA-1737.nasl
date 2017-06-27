#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1737. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35907);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2009-0366", "CVE-2009-0367");
  script_osvdb_id(52672);
  script_xref(name:"DSA", value:"1737");

  script_name(english:"Debian DSA-1737-1 : wesnoth - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security issues have been discovered in wesnoth, a fantasy
turn-based strategy game. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2009-0366
    Daniel Franke discovered that the wesnoth server is
    prone to a denial of service attack when receiving
    special crafted compressed data.

  - CVE-2009-0367
    Daniel Franke discovered that the sandbox implementation
    for the python AIs can be used to execute arbitrary
    python code on wesnoth clients. In order to prevent this
    issue, the python support has been disabled. A
    compatibility patch was included, so that the affected
    campagne is still working properly."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1737"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wesnoth packages.

For the stable distribution (lenny), these problems have been fixed in
version 1.4.4-2+lenny1.

For the oldstable distribution (etch), these problems have been fixed
in version 1.2-5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/12");
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
if (deb_check(release:"4.0", prefix:"wesnoth", reference:"1.2-5")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-data", reference:"1.2-5")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-editor", reference:"1.2-5")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-ei", reference:"1.2-5")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-httt", reference:"1.2-5")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-music", reference:"1.2-5")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-server", reference:"1.2-5")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-trow", reference:"1.2-5")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-tsg", reference:"1.2-5")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-ttb", reference:"1.2-5")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-utbs", reference:"1.2-5")) flag++;
if (deb_check(release:"5.0", prefix:"wesnoth", reference:"1.4.4-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wesnoth-all", reference:"1.4.4-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wesnoth-aoi", reference:"1.4.4-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wesnoth-data", reference:"1.4.4-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wesnoth-dbg", reference:"1.4.4-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wesnoth-did", reference:"1.4.4-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wesnoth-editor", reference:"1.4.4-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wesnoth-ei", reference:"1.4.4-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wesnoth-httt", reference:"1.4.4-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wesnoth-l", reference:"1.4.4-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wesnoth-music", reference:"1.4.4-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wesnoth-nr", reference:"1.4.4-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wesnoth-server", reference:"1.4.4-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wesnoth-sof", reference:"1.4.4-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wesnoth-sotbe", reference:"1.4.4-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wesnoth-thot", reference:"1.4.4-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wesnoth-tools", reference:"1.4.4-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wesnoth-trow", reference:"1.4.4-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wesnoth-tsg", reference:"1.4.4-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wesnoth-ttb", reference:"1.4.4-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"wesnoth-utbs", reference:"1.4.4-2+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
