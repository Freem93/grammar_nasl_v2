#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-539. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15376);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/18 00:11:36 $");

  script_cve_id("CVE-2004-0689");
  script_osvdb_id(8589);
  script_xref(name:"DSA", value:"539");

  script_name(english:"Debian DSA-539-1 : kdelibs - temporary directory vulnerability");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE security team was alerted that in some cases the integrity of
symlinks used by KDE are not ensured and that these symlinks can be
pointing to stale locations. This can be abused by a local attacker to
create or truncate arbitrary files or to prevent KDE applications from
functioning correctly."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-539"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kde packages.

For the stable distribution (woody) this problem has been fixed in
version 2.2.2-13.woody.12."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/11");
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
if (deb_check(release:"3.0", prefix:"kdelibs-dev", reference:"2.2.2-13.woody.12")) flag++;
if (deb_check(release:"3.0", prefix:"kdelibs3", reference:"2.2.2-13.woody.12")) flag++;
if (deb_check(release:"3.0", prefix:"kdelibs3-bin", reference:"2.2.2-13.woody.12")) flag++;
if (deb_check(release:"3.0", prefix:"kdelibs3-cups", reference:"2.2.2-13.woody.12")) flag++;
if (deb_check(release:"3.0", prefix:"kdelibs3-doc", reference:"2.2.2-13.woody.12")) flag++;
if (deb_check(release:"3.0", prefix:"libarts", reference:"2.2.2-13.woody.12")) flag++;
if (deb_check(release:"3.0", prefix:"libarts-alsa", reference:"2.2.2-13.woody.12")) flag++;
if (deb_check(release:"3.0", prefix:"libarts-dev", reference:"2.2.2-13.woody.12")) flag++;
if (deb_check(release:"3.0", prefix:"libkmid", reference:"2.2.2-13.woody.12")) flag++;
if (deb_check(release:"3.0", prefix:"libkmid-alsa", reference:"2.2.2-13.woody.12")) flag++;
if (deb_check(release:"3.0", prefix:"libkmid-dev", reference:"2.2.2-13.woody.12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
