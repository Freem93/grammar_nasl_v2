#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-795-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(96704);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/03/08 15:07:20 $");

  script_cve_id("CVE-2016-10092", "CVE-2016-10093", "CVE-2016-3622", "CVE-2016-3623", "CVE-2016-3624", "CVE-2016-3945", "CVE-2016-3990", "CVE-2016-9533", "CVE-2016-9534", "CVE-2016-9535", "CVE-2016-9536", "CVE-2016-9537", "CVE-2016-9538", "CVE-2016-9540", "CVE-2017-5225");
  script_osvdb_id(136741, 136836, 136837, 136839, 137083, 145021, 145022, 145023, 145751, 145752, 147758, 147779, 148165, 148170, 149991);

  script_name(english:"Debian DLA-795-1 : tiff security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Numerous security vulnerabilities have been found through fuzzing on
various tiff-related binaries. Crafted TIFF images allows remote
attacks to cause denial of service or, in certain cases arbitrary code
execution through divide-by-zero, out of bunds write, integer and heap
overflow.

CVE-2016-3622

The fpAcc function in tif_predict.c in the tiff2rgba tool in LibTIFF
4.0.6 and earlier allows remote attackers to cause a denial of service
(divide-by-zero error) via a crafted TIFF image.

CVE-2016-3623

The rgb2ycbcr tool in LibTIFF 4.0.6 and earlier allows remote
attackers to cause a denial of service (divide-by-zero) by setting the
(1) v or (2) h parameter to 0. (Fixed along with CVE-2016-3624.)

CVE-2016-3624

The cvtClump function in the rgb2ycbcr tool in LibTIFF 4.0.6 and
earlier allows remote attackers to cause a denial of service
(out-of-bounds write) by setting the '-v' option to -1.

CVE-2016-3945

Multiple integer overflows in the (1) cvt_by_strip and (2) cvt_by_tile
functions in the tiff2rgba tool in LibTIFF 4.0.6 and earlier, when -b
mode is enabled, allow remote attackers to cause a denial of service
(crash) or execute arbitrary code via a crafted TIFF image, which
triggers an out-of-bounds write.

CVE-2016-3990

Heap-based buffer overflow in the horizontalDifference8 function in
tif_pixarlog.c in LibTIFF 4.0.6 and earlier allows remote attackers to
cause a denial of service (crash) or execute arbitrary code via a
crafted TIFF image to tiffcp.

CVE-2016-9533

tif_pixarlog.c in libtiff 4.0.6 has out-of-bounds write
vulnerabilities in heap allocated buffers. Reported as MSVR 35094, aka
'PixarLog horizontalDifference heap-buffer-overflow.'

CVE-2016-9534

tif_write.c in libtiff 4.0.6 has an issue in the error code path of
TIFFFlushData1() that didn't reset the tif_rawcc and tif_rawcp
members. Reported as MSVR 35095, aka 'TIFFFlushData1
heap-buffer-overflow.'

CVE-2016-9535

tif_predict.h and tif_predict.c in libtiff 4.0.6 have assertions that
can lead to assertion failures in debug mode, or buffer overflows in
release mode, when dealing with unusual tile size like YCbCr with
subsampling. Reported as MSVR 35105, aka 'Predictor
heap-buffer-overflow.'

CVE-2016-9536

tools/tiff2pdf.c in libtiff 4.0.6 has out-of-bounds write
vulnerabilities in heap allocated buffers in t2p_process_jpeg_strip().
Reported as MSVR 35098, aka 't2p_process_jpeg_strip
heap-buffer-overflow.'

CVE-2016-9537

tools/tiffcrop.c in libtiff 4.0.6 has out-of-bounds write
vulnerabilities in buffers. Reported as MSVR 35093, MSVR 35096, and
MSVR 35097.

CVE-2016-9538

tools/tiffcrop.c in libtiff 4.0.6 reads an undefined buffer in
readContigStripsIntoBuffer() because of a uint16 integer overflow.
Reported as MSVR 35100.

CVE-2016-9540

tools/tiffcp.c in libtiff 4.0.6 has an out-of-bounds write on tiled
images with odd tile width versus image width. Reported as MSVR 35103,
aka cpStripToTile heap-buffer-overflow.

CVE-2016-10092

heap-buffer-overflow in tiffcrop

CVE-2016-10093 uint32 underflow/overflow that can cause heap-based
buffer overflow in tiffcp

CVE-2017-5225

LibTIFF version 4.0.7 is vulnerable to a heap buffer overflow in the
tools/tiffcp resulting in DoS or code execution via a crafted
BitsPerSample value.

Bug #846837

heap-based buffer verflow in TIFFFillStrip (tif_read.c)

For Debian 7 'Wheezy', these problems have been fixed in version
4.0.2-6+deb7u9.

We recommend that you upgrade your tiff packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/01/msg00031.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/tiff"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff5-alt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiffxx5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/24");
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
if (deb_check(release:"7.0", prefix:"libtiff-doc", reference:"4.0.2-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff-opengl", reference:"4.0.2-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff-tools", reference:"4.0.2-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff5", reference:"4.0.2-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff5-alt-dev", reference:"4.0.2-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff5-dev", reference:"4.0.2-6+deb7u9")) flag++;
if (deb_check(release:"7.0", prefix:"libtiffxx5", reference:"4.0.2-6+deb7u9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
