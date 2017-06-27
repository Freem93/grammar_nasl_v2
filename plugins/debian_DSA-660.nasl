#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-660. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16262);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2005-0078");
  script_osvdb_id(13204);
  script_xref(name:"DSA", value:"660");

  script_name(english:"Debian DSA-660-1 : kdebase - missing return value check");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Raphael Enrici discovered that the KDE screensaver can crash under
certain local circumstances. This can be exploited by an attacker with
physical access to the workstation to take over the desktop session."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-660"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kscreensaver package.

For the stable distribution (woody) this problem has been fixed in
version 2.2.2-14.9.

This problem has been fixed upstream in KDE 3.0.5 and is therefore
fixed in the unstable (sid) and testing (sarge) distributions already."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/26");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"kate", reference:"2.2.2-14.9")) flag++;
if (deb_check(release:"3.0", prefix:"kdebase", reference:"2.2.2-14.9")) flag++;
if (deb_check(release:"3.0", prefix:"kdebase-audiolibs", reference:"2.2.2-14.9")) flag++;
if (deb_check(release:"3.0", prefix:"kdebase-dev", reference:"2.2.2-14.9")) flag++;
if (deb_check(release:"3.0", prefix:"kdebase-doc", reference:"2.2.2-14.9")) flag++;
if (deb_check(release:"3.0", prefix:"kdebase-libs", reference:"2.2.2-14.9")) flag++;
if (deb_check(release:"3.0", prefix:"kdewallpapers", reference:"2.2.2-14.9")) flag++;
if (deb_check(release:"3.0", prefix:"kdm", reference:"2.2.2-14.9")) flag++;
if (deb_check(release:"3.0", prefix:"konqueror", reference:"2.2.2-14.9")) flag++;
if (deb_check(release:"3.0", prefix:"konsole", reference:"2.2.2-14.9")) flag++;
if (deb_check(release:"3.0", prefix:"kscreensaver", reference:"2.2.2-14.9")) flag++;
if (deb_check(release:"3.0", prefix:"libkonq-dev", reference:"2.2.2-14.9")) flag++;
if (deb_check(release:"3.0", prefix:"libkonq3", reference:"2.2.2-14.9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
