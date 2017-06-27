#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1562. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32086);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/08/21 14:15:32 $");

  script_cve_id("CVE-2008-1380");
  script_osvdb_id(44467);
  script_xref(name:"DSA", value:"1562");

  script_name(english:"Debian DSA-1562-1 : iceape - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that crashes in the JavaScript engine of Iceape, an
unbranded version of the SeaMonkey internet suite could potentially
lead to the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1562"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the iceape packages.

For the stable distribution (etch), this problem has been fixed in
version 1.0.13~pre080323b-0etch3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceape");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/01");
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
if (deb_check(release:"4.0", prefix:"iceape", reference:"1.0.13~pre080323b-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-browser", reference:"1.0.13~pre080323b-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-calendar", reference:"1.0.13~pre080323b-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-chatzilla", reference:"1.0.13~pre080323b-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-dbg", reference:"1.0.13~pre080323b-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-dev", reference:"1.0.13~pre080323b-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-dom-inspector", reference:"1.0.13~pre080323b-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-gnome-support", reference:"1.0.13~pre080323b-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"iceape-mailnews", reference:"1.0.13~pre080323b-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla", reference:"1.8+1.0.13~pre080323b-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-browser", reference:"1.8+1.0.13~pre080323b-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-calendar", reference:"1.8+1.0.13~pre080323b-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-chatzilla", reference:"1.8+1.0.13~pre080323b-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-dev", reference:"1.8+1.0.13~pre080323b-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-dom-inspector", reference:"1.8+1.0.13~pre080323b-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-js-debugger", reference:"1.8+1.0.13~pre080323b-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-mailnews", reference:"1.8+1.0.13~pre080323b-0etch3")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-psm", reference:"1.8+1.0.13~pre080323b-0etch3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
