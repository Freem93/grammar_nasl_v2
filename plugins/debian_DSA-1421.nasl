#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1421. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29228);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-5742", "CVE-2007-6201");
  script_osvdb_id(41712, 41713);
  script_xref(name:"DSA", value:"1421");

  script_name(english:"Debian DSA-1421-1 : wesnoth - directory traversal");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability has been discovered in Battle for Wesnoth that allows
remote attackers to read arbitrary files the user running the client
has access to on the machine running the game client."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1421"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wesnoth package.

For the old stable distribution (sarge) this problem has been fixed in
version 0.9.0-7.

For the stable distribution (etch) this problem has been fixed in
version 1.2-3.

For the stable backports distribution (etch-backports) this problem
has been fixed in version 1.2.8-1~bpo40+1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_cwe_id(20, 22);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"wesnoth", reference:"0.9.0-7")) flag++;
if (deb_check(release:"3.1", prefix:"wesnoth-data", reference:"0.9.0-7")) flag++;
if (deb_check(release:"3.1", prefix:"wesnoth-editor", reference:"0.9.0-7")) flag++;
if (deb_check(release:"3.1", prefix:"wesnoth-ei", reference:"0.9.0-7")) flag++;
if (deb_check(release:"3.1", prefix:"wesnoth-httt", reference:"0.9.0-7")) flag++;
if (deb_check(release:"3.1", prefix:"wesnoth-music", reference:"0.9.0-7")) flag++;
if (deb_check(release:"3.1", prefix:"wesnoth-server", reference:"0.9.0-7")) flag++;
if (deb_check(release:"3.1", prefix:"wesnoth-sotbe", reference:"0.9.0-7")) flag++;
if (deb_check(release:"3.1", prefix:"wesnoth-tdh", reference:"0.9.0-7")) flag++;
if (deb_check(release:"3.1", prefix:"wesnoth-trow", reference:"0.9.0-7")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth", reference:"1.2-3")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-data", reference:"1.2-3")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-editor", reference:"1.2-3")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-ei", reference:"1.2-3")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-httt", reference:"1.2-3")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-music", reference:"1.2-3")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-server", reference:"1.2-3")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-trow", reference:"1.2-3")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-tsg", reference:"1.2-3")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-ttb", reference:"1.2-3")) flag++;
if (deb_check(release:"4.0", prefix:"wesnoth-utbs", reference:"1.2-3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
