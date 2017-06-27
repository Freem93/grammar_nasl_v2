#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-434-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88995);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/07/06 14:12:41 $");

  script_cve_id("CVE-2015-4491", "CVE-2015-7673", "CVE-2015-7674");
  script_osvdb_id(126022, 128371, 128372);

  script_name(english:"Debian DLA-434-1 : gtk+2.0 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Gustavo Grieco discovered different security issues in Gtk+2.0's
gdk-pixbuf.

CVE-2015-4491

Heap overflow when processing BMP images which may allow to execute of
arbitrary code via malformed images.

CVE-2015-7673

Heap overflow when processing TGA images which may allow execute
arbitrary code or denial of service (process crash) via malformed
images.

CVE-2015-7674

Integer overflow when processing GIF images which may allow to execute
arbitrary code or denial of service (process crash) via malformed
image.

For Debian 6 'Squeeze', these issues have been fixed in gtk+2.0
version 2.20.1-2+deb6u2. We recommend you to upgrade your gtk+2.0
packages.

Learn more about the Debian Long Term Support (LTS) Project and how to
apply these updates at: https://wiki.debian.org/LTS/

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/02/msg00026.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/gtk+2.0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.debian.org/LTS/"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gtk2-engines-pixbuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gtk2.0-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgail-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgail-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgail-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgail-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgail18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgtk2.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgtk2.0-0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgtk2.0-0-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgtk2.0-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgtk2.0-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgtk2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgtk2.0-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/29");
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
if (deb_check(release:"6.0", prefix:"gtk2-engines-pixbuf", reference:"2.20.1-2+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"gtk2.0-examples", reference:"2.20.1-2+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libgail-common", reference:"2.20.1-2+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libgail-dbg", reference:"2.20.1-2+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libgail-dev", reference:"2.20.1-2+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libgail-doc", reference:"2.20.1-2+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libgail18", reference:"2.20.1-2+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libgtk2.0-0", reference:"2.20.1-2+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libgtk2.0-0-dbg", reference:"2.20.1-2+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libgtk2.0-0-udeb", reference:"2.20.1-2+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libgtk2.0-bin", reference:"2.20.1-2+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libgtk2.0-common", reference:"2.20.1-2+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libgtk2.0-dev", reference:"2.20.1-2+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libgtk2.0-doc", reference:"2.20.1-2+deb6u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
