#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-673-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94204);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/03 14:55:08 $");

  script_cve_id("CVE-2016-7966");
  script_osvdb_id(145161);

  script_name(english:"Debian DLA-673-1 : kdepimlibs security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Roland Tapken discovered that insufficient input sanitizing in KMail's
plain text viewer allowed attackers the injection of HTML code. This
might open the way to the exploitation of other vulnerabilities in the
HTML viewer code, which is disabled by default.

For Debian 7 'Wheezy', these problems have been fixed in version
4:4.8.4-2+deb7u1.

We recommend that you upgrade your kdepimlibs packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/10/msg00028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/kdepimlibs"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdepimlibs-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdepimlibs-kio-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdepimlibs5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libakonadi-calendar4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libakonadi-contact4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libakonadi-kabc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libakonadi-kcal4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libakonadi-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libakonadi-kmime4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libakonadi-notes4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgpgme++2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkabc4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkalarmcal2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkblog4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkcal4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkcalcore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkcalutils4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkholidays4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkimap4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkldap4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkmbox4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkmime4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkontactinterface4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkpimidentities4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkpimtextedit4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkpimutils4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkresources4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libktnef4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkxmlrpcclient4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmailtransport4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmicroblog4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libqgpgme1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsyndication4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/22");
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
if (deb_check(release:"7.0", prefix:"kdepimlibs-dbg", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"kdepimlibs-kio-plugins", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"kdepimlibs5-dev", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libakonadi-calendar4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libakonadi-contact4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libakonadi-kabc4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libakonadi-kcal4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libakonadi-kde4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libakonadi-kmime4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libakonadi-notes4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgpgme++2", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libkabc4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libkalarmcal2", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libkblog4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libkcal4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libkcalcore4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libkcalutils4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libkholidays4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libkimap4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libkldap4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libkmbox4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libkmime4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libkontactinterface4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libkpimidentities4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libkpimtextedit4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libkpimutils4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libkresources4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libktnef4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libkxmlrpcclient4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmailtransport4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libmicroblog4", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libqgpgme1", reference:"4:4.8.4-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsyndication4", reference:"4:4.8.4-2+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
