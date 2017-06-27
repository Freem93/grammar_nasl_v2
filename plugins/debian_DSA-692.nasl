#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-692. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17299);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-0205");
  script_osvdb_id(14275);
  script_xref(name:"DSA", value:"692");

  script_name(english:"Debian DSA-692-1 : kdenetwork - design flaw");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The KDE team fixed a bug in kppp in 2002 which was now discovered to
be exploitable by iDEFENSE. By opening a sufficiently large number of
file descriptors before executing kppp which is installed setuid root
a local attacker is able to take over privileged file descriptors."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-692"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kppp package.

For the stable distribution (woody) this problem has been fixed in
version 2.2.2-14.7."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/09");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/28");
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
if (deb_check(release:"3.0", prefix:"kdict", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"kit", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"klisa", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"kmail", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"knewsticker", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"knode", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"korn", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"kppp", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"ksirc", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"ktalkd", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"libkdenetwork1", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"libmimelib-dev", reference:"2.2.2-14.7")) flag++;
if (deb_check(release:"3.0", prefix:"libmimelib1", reference:"2.2.2-14.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
