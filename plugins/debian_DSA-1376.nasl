#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1376. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(26079);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/05/17 23:45:44 $");

  script_cve_id("CVE-2007-4569");
  script_xref(name:"DSA", value:"1376");

  script_name(english:"Debian DSA-1376-1 : kdebase - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"iKees Huijgen discovered that under certain circumstances KDM, an X
session manager for KDE, could be tricked into allowing user logins
without a password."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1376"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kdebase package.

For the old stable distribution (sarge), this problem was not present.

For the stable distribution (etch), this problem has been fixed in
version 4:3.5.5a.dfsg.1-6etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/24");
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
if (deb_check(release:"4.0", prefix:"kappfinder", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kate", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kcontrol", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kdebase", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kdebase-bin", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kdebase-data", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kdebase-dbg", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kdebase-dev", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kdebase-doc", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kdebase-doc-html", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kdebase-kio-plugins", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kdepasswd", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kdeprint", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kdesktop", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kdm", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kfind", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"khelpcenter", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kicker", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"klipper", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kmenuedit", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"konqueror", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"konqueror-nsplugins", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"konsole", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kpager", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kpersonalizer", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ksmserver", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ksplash", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ksysguard", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ksysguardd", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"ktip", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"kwin", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libkonq4", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libkonq4-dev", reference:"4:3.5.5a.dfsg.1-6etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
