#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-644-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93847);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/06 20:03:52 $");

  script_cve_id("CVE-2015-1872", "CVE-2015-5479", "CVE-2016-7393");
  script_bugtraq_id(72644, 75932);
  script_osvdb_id(112932, 118095, 124921);

  script_name(english:"Debian DLA-644-1 : libav security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been found in libav :

CVE-2015-1872

The ff_mjpeg_decode_sof function in libavcodec/mjpegdec.c in Libav
before 0.8.18 does not validate the number of components in a JPEG-LS
Start Of Frame segment, which allows remote attackers to cause a
denial of service (out-of-bounds array access) or possibly have
unspecified other impact via crafted Motion JPEG data.

CVE-2015-5479

The ff_h263_decode_mba function in libavcodec/ituh263dec.c in Libav
before 11.5 allows remote attackers to cause a denial of service
(divide-by-zero error and application crash) via a file with crafted
dimensions.

CVE-2016-7393

The aac_sync function in libavcodec/aac_parser.c in Libav before 11.5
is vulnerable to a stack-based buffer overflow.

For Debian 7 'Wheezy', these problems have been fixed in version
6:0.8.18-0+deb7u1.

We recommend that you upgrade your libav packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/10/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libav"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/05");
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
if (deb_check(release:"7.0", prefix:"ffmpeg", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ffmpeg-dbg", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ffmpeg-doc", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libav-dbg", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libav-doc", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libav-extra-dbg", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libav-tools", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavcodec-dev", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavcodec-extra-53", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavcodec53", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavdevice-dev", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavdevice-extra-53", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavdevice53", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavfilter-dev", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavfilter-extra-2", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavfilter2", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavformat-dev", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavformat-extra-53", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavformat53", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavutil-dev", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavutil-extra-51", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libavutil51", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpostproc-dev", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpostproc-extra-52", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpostproc52", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libswscale-dev", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libswscale-extra-2", reference:"6:0.8.18-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libswscale2", reference:"6:0.8.18-0+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
