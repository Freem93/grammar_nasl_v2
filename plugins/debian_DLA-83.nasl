#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-83-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82228);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/12/02 20:16:13 $");

  script_name(english:"Debian DLA-83-1 : ffmpeg update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update to ffmpeg disables support for over 100 codecs, decoders,
and formats that are rarely used nowadays, for which the support
available in squeeze is most likely insufficient, etc.

This update is only meant to reduce the attack surface.

ffmpeg is otherwise unsupported in squeeze-lts, and any use of it with
untrusted data is highly discouraged.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/11/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/ffmpeg"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ffmpeg-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ffmpeg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavcodec52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavdevice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavdevice52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavfilter0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavformat-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavformat52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavutil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libavutil49");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpostproc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpostproc51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswscale-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libswscale0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"ffmpeg", reference:"4:0.5.10-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"ffmpeg-dbg", reference:"4:0.5.10-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"ffmpeg-doc", reference:"4:0.5.10-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libavcodec-dev", reference:"4:0.5.10-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libavcodec52", reference:"4:0.5.10-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libavdevice-dev", reference:"4:0.5.10-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libavdevice52", reference:"4:0.5.10-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libavfilter-dev", reference:"4:0.5.10-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libavfilter0", reference:"4:0.5.10-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libavformat-dev", reference:"4:0.5.10-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libavformat52", reference:"4:0.5.10-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libavutil-dev", reference:"4:0.5.10-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libavutil49", reference:"4:0.5.10-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libpostproc-dev", reference:"4:0.5.10-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libpostproc51", reference:"4:0.5.10-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libswscale-dev", reference:"4:0.5.10-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libswscale0", reference:"4:0.5.10-1+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
