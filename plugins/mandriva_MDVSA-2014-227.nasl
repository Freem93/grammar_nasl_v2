#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:227. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(79573);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/26 11:47:20 $");

  script_cve_id("CVE-2013-0848", "CVE-2013-0852", "CVE-2013-0860", "CVE-2013-3672", "CVE-2013-3674", "CVE-2013-7020");
  script_bugtraq_id(60492, 63796, 63936, 63941);
  script_xref(name:"MDVSA", value:"2014:227");

  script_name(english:"Mandriva Linux Security Advisory : ffmpeg (MDVSA-2014:227)");
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
"Multiple vulnerabilities has been discovered and corrected in ffmpeg :

The decode_init function in libavcodec/huffyuv.c in FFmpeg before 1.1
allows remote attackers to have an unspecified impact via a crafted
width in huffyuv data with the predictor set to median and the
colorspace set to YUV422P, which triggers an out-of-bounds array
access (CVE-2013-0848).

The parse_picture_segment function in libavcodec/pgssubdec.c in FFmpeg
before 1.1 allows remote attackers to have an unspecified impact via
crafted RLE data, which triggers an out-of-bounds array access
(CVE-2013-0852).

The ff_er_frame_end function in libavcodec/error_resilience.c in
FFmpeg before 1.0.4 and 1.1.x before 1.1.1 does not properly verify
that a frame is fully initialized, which allows remote attackers to
trigger a NULL pointer dereference via crafted picture data
(CVE-2013-0860).

The mm_decode_inter function in mmvideo.c in libavcodec in FFmpeg
before 1.2.1 does not validate the relationship between a horizontal
coordinate and a width value, which allows remote attackers to cause a
denial of service (out-of-bounds array access and application crash)
via crafted American Laser Games (ALG) MM Video data (CVE-2013-3672).

The cdg_decode_frame function in cdgraphics.c in libavcodec in FFmpeg
before 1.2.1 does not validate the presence of non-header data in a
buffer, which allows remote attackers to cause a denial of service
(out-of-bounds array access and application crash) via crafted CD
Graphics Video data (CVE-2013-3674).

The read_header function in libavcodec/ffv1dec.c in FFmpeg before 2.1
does not properly enforce certain bit-count and colorspace
constraints, which allows remote attackers to cause a denial of
service (out-of-bounds array access) or possibly have unspecified
other impact via crafted FFV1 data (CVE-2013-7020).

The updated packages have been upgraded to the 0.10.15 version which
is not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.ffmpeg.org/security.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avcodec53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avfilter2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avformat53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avutil51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ffmpeg-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ffmpeg-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64postproc52");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64swresample0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64swscaler2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"ffmpeg-0.10.15-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64avcodec53-0.10.15-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64avfilter2-0.10.15-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64avformat53-0.10.15-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64avutil51-0.10.15-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64ffmpeg-devel-0.10.15-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64ffmpeg-static-devel-0.10.15-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64postproc52-0.10.15-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64swresample0-0.10.15-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64swscaler2-0.10.15-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
