#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-296. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15133);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/18 00:07:15 $");

  script_cve_id("CVE-2003-0204");
  script_bugtraq_id(7318);
  script_xref(name:"DSA", value:"296");

  script_name(english:"Debian DSA-296-1 : kdebase - insecure execution");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The KDE team discovered a vulnerability in the way KDE uses
Ghostscript software for processing of PostScript (PS) and PDF files.
An attacker could provide a malicious PostScript or PDF file via mail
or websites that could lead to executing arbitrary commands under the
privileges of the user viewing the file or when the browser generates
a directory listing with thumbnails."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-296"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kdebase and associated packages.

For the stable distribution (woody) this problem has been fixed in
version 2.2.2-14.4 of kdebase and associated packages.

The old stable distribution (potato) is not affected since it does not
contain KDE.

For the unofficial backport of KDE 3.1.1 to woody by Ralf Nolden on
download.kde.org, this problem has been fixed in version 3.1.1-0woody3
of kdebase. Using the normal backport line for apt-get you will get
the update :

  deb http://download.kde.org/stable/latest/Debian stable main"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"kate", reference:"2.2.2-14.4")) flag++;
if (deb_check(release:"3.0", prefix:"kdebase", reference:"2.2.2-14.4")) flag++;
if (deb_check(release:"3.0", prefix:"kdebase-audiolibs", reference:"2.2.2-14.4")) flag++;
if (deb_check(release:"3.0", prefix:"kdebase-dev", reference:"2.2.2-14.4")) flag++;
if (deb_check(release:"3.0", prefix:"kdebase-doc", reference:"2.2.2-14.4")) flag++;
if (deb_check(release:"3.0", prefix:"kdebase-libs", reference:"2.2.2-14.4")) flag++;
if (deb_check(release:"3.0", prefix:"kdewallpapers", reference:"2.2.2-14.4")) flag++;
if (deb_check(release:"3.0", prefix:"kdm", reference:"2.2.2-14.4")) flag++;
if (deb_check(release:"3.0", prefix:"konqueror", reference:"2.2.2-14.4")) flag++;
if (deb_check(release:"3.0", prefix:"konsole", reference:"2.2.2-14.4")) flag++;
if (deb_check(release:"3.0", prefix:"kscreensaver", reference:"2.2.2-14.4")) flag++;
if (deb_check(release:"3.0", prefix:"libkonq-dev", reference:"2.2.2-14.4")) flag++;
if (deb_check(release:"3.0", prefix:"libkonq3", reference:"2.2.2-14.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
