#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1618. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33738);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-2376", "CVE-2008-2662", "CVE-2008-2663", "CVE-2008-2664", "CVE-2008-2725", "CVE-2008-2726");
  script_osvdb_id(46550, 46551, 46552, 46553, 46554, 46691);
  script_xref(name:"DSA", value:"1618");

  script_name(english:"Debian DSA-1618-1 : ruby1.9 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the interpreter for
the Ruby language, which may lead to denial of service or the
execution of arbitrary code. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2008-2662
    Drew Yao discovered that multiple integer overflows in
    the string processing code may lead to denial of service
    and potentially the execution of arbitrary code.

  - CVE-2008-2663
    Drew Yao discovered that multiple integer overflows in
    the string processing code may lead to denial of service
    and potentially the execution of arbitrary code.

  - CVE-2008-2664
    Drew Yao discovered that a programming error in the
    string processing code may lead to denial of service and
    potentially the execution of arbitrary code.

  - CVE-2008-2725
    Drew Yao discovered that an integer overflow in the
    array handling code may lead to denial of service and
    potentially the execution of arbitrary code.

  - CVE-2008-2726
    Drew Yao discovered that an integer overflow in the
    array handling code may lead to denial of service and
    potentially the execution of arbitrary code.

  - CVE-2008-2376
    It was discovered that an integer overflow in the array
    handling code may lead to denial of service and
    potentially the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-2376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1618"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ruby1.9 packages.

For the stable distribution (etch), these problems have been fixed in
version 1.9.0+20060609-1etch2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"irb1.9", reference:"1.9.0+20060609-1etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libdbm-ruby1.9", reference:"1.9.0+20060609-1etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libgdbm-ruby1.9", reference:"1.9.0+20060609-1etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libopenssl-ruby1.9", reference:"1.9.0+20060609-1etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libreadline-ruby1.9", reference:"1.9.0+20060609-1etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libruby1.9", reference:"1.9.0+20060609-1etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libruby1.9-dbg", reference:"1.9.0+20060609-1etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libtcltk-ruby1.9", reference:"1.9.0+20060609-1etch2")) flag++;
if (deb_check(release:"4.0", prefix:"rdoc1.9", reference:"1.9.0+20060609-1etch2")) flag++;
if (deb_check(release:"4.0", prefix:"ri1.9", reference:"1.9.0+20060609-1etch2")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.9", reference:"1.9.0+20060609-1etch2")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.9-dev", reference:"1.9.0+20060609-1etch2")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.9-elisp", reference:"1.9.0+20060609-1etch2")) flag++;
if (deb_check(release:"4.0", prefix:"ruby1.9-examples", reference:"1.9.0+20060609-1etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
