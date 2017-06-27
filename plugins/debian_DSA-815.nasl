#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-815. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19711);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/18 00:15:59 $");

  script_cve_id("CVE-2005-2494");
  script_osvdb_id(19220);
  script_xref(name:"DSA", value:"815");

  script_name(english:"Debian DSA-815-1 : kdebase - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ilja van Sprundel discovered a serious lock file handling error in
kcheckpass that can, in some configurations, be used to gain root
access."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-815"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kdebase-bin package.

The old stable distribution (woody) is not affected by this problem.

For the stable distribution (sarge) this problem has been fixed in
version 3.3.2-1sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"kappfinder", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kate", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kcontrol", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kdebase", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kdebase-bin", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kdebase-data", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kdebase-dev", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kdebase-doc", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kdebase-kio-plugins", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kdepasswd", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kdeprint", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kdesktop", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kdm", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kfind", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"khelpcenter", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kicker", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"klipper", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kmenuedit", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"konqueror", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"konqueror-nsplugins", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"konsole", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kpager", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kpersonalizer", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ksmserver", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ksplash", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ksysguard", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ksysguardd", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"ktip", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"kwin", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libkonq4", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libkonq4-dev", reference:"3.3.2-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"xfonts-konsole", reference:"3.3.2-1sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
