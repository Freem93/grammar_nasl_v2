#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-943-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100225);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/17 14:19:06 $");

  script_name(english:"Debian DLA-943-1 : deluge security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there was a directory traversal attack
vulnerability in the web user interface web in the deluge bittorrent
client.

For Debian 7 'Wheezy', this issue has been fixed in deluge version
1.3.3-2+nmu1+deb7u2.

We recommend that you upgrade your deluge packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/05/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/deluge"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:deluge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:deluge-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:deluge-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:deluge-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:deluge-torrent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:deluge-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:deluge-webui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:deluged");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"deluge", reference:"1.3.3-2+nmu1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"deluge-common", reference:"1.3.3-2+nmu1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"deluge-console", reference:"1.3.3-2+nmu1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"deluge-gtk", reference:"1.3.3-2+nmu1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"deluge-torrent", reference:"1.3.3-2+nmu1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"deluge-web", reference:"1.3.3-2+nmu1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"deluge-webui", reference:"1.3.3-2+nmu1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"deluged", reference:"1.3.3-2+nmu1+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
