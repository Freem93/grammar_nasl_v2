#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-740-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95665);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2016/12/12 14:40:36 $");

  script_cve_id("CVE-2016-9888");
  script_osvdb_id(148390);

  script_name(english:"Debian DLA-740-1 : libgsf security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there was a NULL pointer deference exploit in
libgsf, a I/O abstraction library for GNOME.

An error within the 'tar_directory_for_file()' function could be
exploited to trigger a NULL pointer dereference and subsequently cause
a crash via a crafted TAR file.

For Debian 7 'Wheezy', this issue has been fixed in libgsf version
1.14.21-2.1+deb7u1.

We recommend that you upgrade your libgsf packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/12/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libgsf"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgsf-1-114");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgsf-1-114-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgsf-1-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgsf-1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgsf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgsf-gnome-1-114");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgsf-gnome-1-114-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgsf-gnome-1-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/12");
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
if (deb_check(release:"7.0", prefix:"libgsf-1-114", reference:"1.14.21-2.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgsf-1-114-dbg", reference:"1.14.21-2.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgsf-1-common", reference:"1.14.21-2.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgsf-1-dev", reference:"1.14.21-2.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgsf-bin", reference:"1.14.21-2.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgsf-gnome-1-114", reference:"1.14.21-2.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgsf-gnome-1-114-dbg", reference:"1.14.21-2.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgsf-gnome-1-dev", reference:"1.14.21-2.1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
