#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1156. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22698);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/05/17 23:41:26 $");

  script_cve_id("CVE-2006-2449");
  script_osvdb_id(26511);
  script_xref(name:"DSA", value:"1156");

  script_name(english:"Debian DSA-1156-1 : kdebase - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ludwig Nussel discovered that kdm, the X display manager for KDE,
handles access to the session type configuration file insecurely,
which may lead to the disclosure of arbitrary files through a symlink
attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=374002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1156"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kdm package.

For the stable distribution (sarge) this problem has been fixed in
version 3.3.2-1sarge3."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"kappfinder", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kate", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kcontrol", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kdebase", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kdebase-bin", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kdebase-data", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kdebase-dev", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kdebase-doc", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kdebase-kio-plugins", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kdepasswd", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kdeprint", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kdesktop", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kdm", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kfind", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"khelpcenter", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kicker", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"klipper", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kmenuedit", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"konqueror", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"konqueror-nsplugins", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"konsole", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kpager", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kpersonalizer", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"ksmserver", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"ksplash", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"ksysguard", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"ksysguardd", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"ktip", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"kwin", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libkonq4", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libkonq4-dev", reference:"3.3.2-1sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"xfonts-konsole", reference:"3.3.2-1sarge3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
