#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1558. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32059);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/05/22 11:11:53 $");

  script_cve_id("CVE-2008-1380");
  script_osvdb_id(44467);
  script_xref(name:"DSA", value:"1558");

  script_name(english:"Debian DSA-1558-1 : xulrunner - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that crashes in the JavaScript engine of xulrunner,
the Gecko engine library, could potentially lead to the execution of
arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1558"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xulrunner packages.

For the stable distribution (etch), this problem has been fixed in
version 1.8.0.15~pre080323b-0etch2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libmozillainterfaces-java", reference:"1.8.0.15~pre080323b-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libmozjs-dev", reference:"1.8.0.15~pre080323b-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libmozjs0d", reference:"1.8.0.15~pre080323b-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libmozjs0d-dbg", reference:"1.8.0.15~pre080323b-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libnspr4-0d", reference:"1.8.0.15~pre080323b-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libnspr4-0d-dbg", reference:"1.8.0.15~pre080323b-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libnspr4-dev", reference:"1.8.0.15~pre080323b-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libnss3-0d", reference:"1.8.0.15~pre080323b-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libnss3-0d-dbg", reference:"1.8.0.15~pre080323b-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libnss3-dev", reference:"1.8.0.15~pre080323b-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libnss3-tools", reference:"1.8.0.15~pre080323b-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libsmjs-dev", reference:"1.8.0.15~pre080323b-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libsmjs1", reference:"1.8.0.15~pre080323b-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libxul-common", reference:"1.8.0.15~pre080323b-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libxul-dev", reference:"1.8.0.15~pre080323b-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libxul0d", reference:"1.8.0.15~pre080323b-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libxul0d-dbg", reference:"1.8.0.15~pre080323b-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"python-xpcom", reference:"1.8.0.15~pre080323b-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"spidermonkey-bin", reference:"1.8.0.15~pre080323b-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"xulrunner", reference:"1.8.0.15~pre080323b-0etch2")) flag++;
if (deb_check(release:"4.0", prefix:"xulrunner-gnome-support", reference:"1.8.0.15~pre080323b-0etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
