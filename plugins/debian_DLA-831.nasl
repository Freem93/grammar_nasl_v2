#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-831-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97236);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/03/07 17:25:24 $");

  script_cve_id("CVE-2017-5884", "CVE-2017-5885");
  script_osvdb_id(151479, 151480);

  script_name(english:"Debian DLA-831-1 : gtk-vnc security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Josef Gajdusek discovered two vulnerabilities in gtk-vnc, a VNC viewer
widget for GTK :

CVE-2017-5884

Fix bounds checking for RRE, hextile & copyrec encodings. This bug
allowed a remote server to cause a denial of service by buffer
overflow via a carefully crafted message containing subrectangles
outside the drawing area.

CVE-2017-5885

Correctly validate color map range indexes. This bug allowed a remote
server to cause a denial of service by buffer overflow via a carefully
crafted message with out-of-range colour values.

For Debian 7 'Wheezy', these problems have been fixed in version
0.5.0-3.1+deb7u1.

We recommend that you upgrade your gtk-vnc packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/02/msg00020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/gtk-vnc"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-gtk-vnc-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gvncviewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgtk-vnc-1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgtk-vnc-1.0-0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgtk-vnc-1.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgtk-vnc-2.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgtk-vnc-2.0-0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgtk-vnc-2.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgvnc-1.0-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgvnc-1.0-0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgvnc-1.0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mozilla-gtk-vnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-gtk-vnc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/21");
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
if (deb_check(release:"7.0", prefix:"gir1.2-gtk-vnc-2.0", reference:"0.5.0-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"gvncviewer", reference:"0.5.0-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgtk-vnc-1.0-0", reference:"0.5.0-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgtk-vnc-1.0-0-dbg", reference:"0.5.0-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgtk-vnc-1.0-dev", reference:"0.5.0-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgtk-vnc-2.0-0", reference:"0.5.0-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgtk-vnc-2.0-0-dbg", reference:"0.5.0-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgtk-vnc-2.0-dev", reference:"0.5.0-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgvnc-1.0-0", reference:"0.5.0-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgvnc-1.0-0-dbg", reference:"0.5.0-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgvnc-1.0-dev", reference:"0.5.0-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"mozilla-gtk-vnc", reference:"0.5.0-3.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python-gtk-vnc", reference:"0.5.0-3.1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
