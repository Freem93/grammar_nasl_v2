#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:173. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82449);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/31 13:56:07 $");

  script_cve_id("CVE-2014-2097", "CVE-2014-2098", "CVE-2014-2099", "CVE-2014-2263", "CVE-2014-4610", "CVE-2014-5271", "CVE-2014-5272", "CVE-2014-8541", "CVE-2014-8542", "CVE-2014-8543", "CVE-2014-8544", "CVE-2014-8545", "CVE-2014-8546", "CVE-2014-8547", "CVE-2014-8548");
  script_xref(name:"MDVSA", value:"2015:173");

  script_name(english:"Mandriva Linux Security Advisory : ffmpeg (MDVSA-2015:173)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ffmpeg packages fix security vulnerabilities :

The tak_decode_frame function in libavcodec/takdec.c in FFmpeg before
2.0.4 does not properly validate a certain bits-per-sample value,
which allows remote attackers to cause a denial of service
(out-of-bounds array access) or possibly have unspecified other impact
via crafted TAK (aka Tom's lossless Audio Kompressor) data
(CVE-2014-2097).

libavcodec/wmalosslessdec.c in FFmpeg before 2.0.4 uses an incorrect
data-structure size for certain coefficients, which allows remote
attackers to cause a denial of service (memory corruption) or possibly
have unspecified other impact via crafted WMA data (CVE-2014-2098).

The msrle_decode_frame function in libavcodec/msrle.c in FFmpeg before
2.0.4 does not properly calculate line sizes, which allows remote
attackers to cause a denial of service (out-of-bounds array access) or
possibly have unspecified other impact via crafted Microsoft RLE video
data (CVE-2014-2099).

The mpegts_write_pmt function in the MPEG2 transport stream (aka DVB)
muxer (libavformat/mpegtsenc.c) in FFmpeg before 2.0.4 allows remote
attackers to have unspecified impact and vectors, which trigger an
out-of-bounds write (CVE-2014-2263).

An integer overflow in LZO decompression in FFmpeg before 2.0.5 allows
remote attackers to have an unspecified impact by embedding compressed
data in a video file (CVE-2014-4610).

A heap-based buffer overflow in the encode_slice function in
libavcodec/proresenc_kostya.c in FFmpeg before 2.0.6 can cause a
crash, allowing a malicious image file to cause a denial of service
(CVE-2014-5271).

libavcodec/iff.c in FFmpeg before 2.0.6 allows an attacker to have an
unspecified impact via a crafted iff image, which triggers an
out-of-bounds array access, related to the rgb8 and rgbn formats
(CVE-2014-5272).

libavcodec/mjpegdec.c in FFmpeg before 2.0.6 considers only dimension
differences, and not bits-per-pixel differences, when determining
whether an image size has changed, which allows remote attackers to
cause a denial of service (out-of-bounds access) or possibly have
unspecified other impact via crafted MJPEG data (CVE-2014-8541).

libavcodec/utils.c in FFmpeg before 2.0.6 omits a certain codec ID
during enforcement of alignment, which allows remote attackers to
cause a denial of service (out-of-bounds access) or possibly have
unspecified other impact via crafted JV data (CVE-2014-8542).

libavcodec/mmvideo.c in FFmpeg before 2.0.6 does not consider all
lines of HHV Intra blocks during validation of image height, which
allows remote attackers to cause a denial of service (out-of-bounds
access) or possibly have unspecified other impact via crafted MM video
data (CVE-2014-8543).

libavcodec/tiff.c in FFmpeg before 2.0.6 does not properly validate
bits-per-pixel fields, which allows remote attackers to cause a denial
of service (out-of-bounds access) or possibly have unspecified other
impact via crafted TIFF data (CVE-2014-8544).

libavcodec/pngdec.c in FFmpeg before 2.0.6 accepts the
monochrome-black format without verifying that the bits-per-pixel
value is 1, which allows remote attackers to cause a denial of service
(out-of-bounds access) or possibly have unspecified other impact via
crafted PNG data (CVE-2014-8545).

Integer underflow in libavcodec/cinepak.c in FFmpeg before 2.0.6
allows remote attackers to cause a denial of service (out-of-bounds
access) or possibly have unspecified other impact via crafted Cinepak
video data (CVE-2014-8546).

libavcodec/gifdec.c in FFmpeg before 2.0.6 does not properly compute
image heights, which allows remote attackers to cause a denial of
service (out-of-bounds access) or possibly have unspecified other
impact via crafted GIF data (CVE-2014-8547).

Off-by-one error in libavcodec/smc.c in FFmpeg before 2.0.6 allows
remote attackers to cause a denial of service (out-of-bounds access)
or possibly have unspecified other impact via crafted Quicktime
Graphics (aka SMC) video data (CVE-2014-8548).

This updates provides ffmpeg version 2.0.6, which fixes these issues
and several other bugs which were corrected upstream."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0280.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0464.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avcodec55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avfilter3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avformat55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avutil52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ffmpeg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ffmpeg-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64postproc52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64swresample0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64swscaler2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"ffmpeg-2.0.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64avcodec55-2.0.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64avfilter3-2.0.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64avformat55-2.0.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64avutil52-2.0.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64ffmpeg-devel-2.0.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64ffmpeg-static-devel-2.0.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64postproc52-2.0.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64swresample0-2.0.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64swscaler2-2.0.6-1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
