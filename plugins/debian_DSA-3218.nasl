#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3218. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82719);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/16 13:48:28 $");

  script_cve_id("CVE-2015-0844");
  script_xref(name:"DSA", value:"3218");

  script_name(english:"Debian DSA-3218-1 : wesnoth-1.10 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ignacio R. Morelle discovered that missing path restrictions in
the'Battle of Wesnoth' game could result in the disclosure of
arbitrary files in the user's home directory if malicious
campaigns/maps are loaded."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/wesnoth-1.10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3218"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wesnoth-1.10 packages.

For the stable distribution (wheezy), this problem has been fixed in
version 1.10.3-3+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"wesnoth", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-aoi", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-core", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-data", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-dbg", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-did", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-dm", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-dw", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-ei", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-httt", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-l", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-low", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-music", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-nr", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-server", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-sof", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-sotbe", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-thot", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-tools", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-trow", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-tsg", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-ttb", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-1.10-utbs", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-core", reference:"1.10.3-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"wesnoth-music", reference:"1.10.3-3+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
