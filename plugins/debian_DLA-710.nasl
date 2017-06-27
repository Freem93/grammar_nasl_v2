#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-710-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94940);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/11/18 14:29:49 $");

  script_name(english:"Debian DLA-710-1 : akonadi update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In some configurations the MySQL storage backend for Akonadi, an
extensible cross-desktop Personal Information Management (PIM) storage
service failed to start after applying the MySQL 5.5.53 security
upgrade.

This update extends the /etc/akonadi/mysql-global.conf configuration
file to restore compatibility (version 1.7.2-3+deb7u1 in Wheezy).

We recommend that you upgrade your akonadi packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/11/msg00017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/akonadi"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:akonadi-backend-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:akonadi-backend-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:akonadi-backend-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:akonadi-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:akonadi-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libakonadi-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libakonadiprotocolinternals1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"akonadi-backend-mysql", reference:"1.7.2-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"akonadi-backend-postgresql", reference:"1.7.2-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"akonadi-backend-sqlite", reference:"1.7.2-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"akonadi-dbg", reference:"1.7.2-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"akonadi-server", reference:"1.7.2-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libakonadi-dev", reference:"1.7.2-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libakonadiprotocolinternals1", reference:"1.7.2-3+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
