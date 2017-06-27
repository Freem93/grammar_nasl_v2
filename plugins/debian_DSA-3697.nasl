#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3697. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94205);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/03 14:55:08 $");

  script_cve_id("CVE-2016-7966");
  script_xref(name:"DSA", value:"3697");

  script_name(english:"Debian DSA-3697-1 : kdepimlibs - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Roland Tapken discovered that insufficient input sanitising in KMail's
plain text viewer allowed the injection of HTML code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/kdepimlibs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3697"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kdepimlibs packages.

For the stable distribution (jessie), this problem has been fixed in
version 4:4.14.2-2+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdepimlibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"kdepimlibs-dbg", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kdepimlibs-kio-plugins", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kdepimlibs5-dev", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libakonadi-calendar4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libakonadi-contact4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libakonadi-kabc4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libakonadi-kcal4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libakonadi-kde4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libakonadi-kmime4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libakonadi-notes4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libakonadi-socialutils4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libakonadi-xml4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libgpgme++2", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkabc4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkalarmcal2", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkblog4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkcal4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkcalcore4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkcalutils4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkholidays4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkimap4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkldap4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkmbox4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkmime4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkontactinterface4a", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkpimidentities4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkpimtextedit4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkpimutils4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkresources4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libktnef4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkxmlrpcclient4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libmailtransport4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libmicroblog4", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libqgpgme1", reference:"4:4.14.2-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libsyndication4", reference:"4:4.14.2-2+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
