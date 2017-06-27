#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-791-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96635);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/03/06 14:38:26 $");

  script_cve_id("CVE-2016-9819", "CVE-2016-9820", "CVE-2016-9821", "CVE-2016-9822");
  script_osvdb_id(148136);

  script_name(english:"Debian DLA-791-1 : libav security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple integer overflows have been discovered in libav 11.8 and
earlier, allowing remote attackers to cause a crash via a crafted MP3
file.

For Debian 7 'Wheezy', these problems have been fixed in version
6:0.8.20-0+deb7u1.

We recommend that you upgrade your libav packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/01/msg00025.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libav"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ffmpeg-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ffmpeg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libav-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libav-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libav-extra-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libav-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec-extra-53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavdevice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavdevice-extra-53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavdevice53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter-extra-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavformat-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavformat-extra-53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavformat53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavutil-extra-51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavutil51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpostproc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpostproc-extra-52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpostproc52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswscale-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswscale-extra-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswscale2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/20");
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
if (deb_check(release:"7.0", prefix:"ffmpeg", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ffmpeg-dbg", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ffmpeg-doc", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libav-dbg", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libav-doc", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libav-extra-dbg", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libav-tools", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavcodec-dev", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavcodec-extra-53", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavcodec53", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavdevice-dev", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavdevice-extra-53", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavdevice53", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavfilter-dev", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavfilter-extra-2", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavfilter2", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavformat-dev", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavformat-extra-53", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavformat53", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavutil-dev", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavutil-extra-51", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavutil51", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpostproc-dev", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpostproc-extra-52", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpostproc52", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libswscale-dev", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libswscale-extra-2", reference:"6:0.8.20-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libswscale2", reference:"6:0.8.20-0+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
