#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1386. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27043);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/05/17 23:45:44 $");

  script_cve_id("CVE-2007-3917");
  script_osvdb_id(41711);
  script_xref(name:"DSA", value:"1386");

  script_name(english:"Debian DSA-1386-1 : wesnoth - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A problem has been discovered in the processing of chat messages.
Overly long messages are truncated by the server to a fixed length,
without paying attention to the multibyte characters. This leads to
invalid UTF-8 on clients and causes an uncaught exception. Note that
both wesnoth and the wesnoth server are affected."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1386"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wesnoth packages.

For the old stable distribution (sarge) this problem has been fixed in
version 0.9.0-6 and in version 1.2.7-1~bpo31+1 of sarge-backports.

For the stable distribution (etch) this problem has been fixed in
version 1.2-2 and in version 1.2.7-1~bpo40+1 of etch-backports.

Packages for the oldstable mips architecture will be added to the
archive later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"wesnoth", reference:"0.9.0-6")) flag++;
if (deb_check(release:"3.1", prefix:"wesnoth-data", reference:"0.9.0-6")) flag++;
if (deb_check(release:"3.1", prefix:"wesnoth-editor", reference:"0.9.0-6")) flag++;
if (deb_check(release:"3.1", prefix:"wesnoth-ei", reference:"0.9.0-6")) flag++;
if (deb_check(release:"3.1", prefix:"wesnoth-httt", reference:"0.9.0-6")) flag++;
if (deb_check(release:"3.1", prefix:"wesnoth-music", reference:"0.9.0-6")) flag++;
if (deb_check(release:"3.1", prefix:"wesnoth-server", reference:"0.9.0-6")) flag++;
if (deb_check(release:"3.1", prefix:"wesnoth-sotbe", reference:"0.9.0-6")) flag++;
if (deb_check(release:"3.1", prefix:"wesnoth-tdh", reference:"0.9.0-6")) flag++;
if (deb_check(release:"3.1", prefix:"wesnoth-trow", reference:"0.9.0-6")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth", reference:"1.2-2")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-data", reference:"1.2-2")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-editor", reference:"1.2-2")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-ei", reference:"1.2-2")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-httt", reference:"1.2-2")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-music", reference:"1.2-2")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-server", reference:"1.2-2")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-trow", reference:"1.2-2")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-tsg", reference:"1.2-2")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-ttb", reference:"1.2-2")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-utbs", reference:"1.2-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
