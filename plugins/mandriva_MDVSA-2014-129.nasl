#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:129. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(76437);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/03/14 13:55:51 $");

  script_cve_id(
    "CVE-2012-2795",
    "CVE-2012-5150",
    "CVE-2014-2098",
    "CVE-2014-2099",
    "CVE-2014-2263",
    "CVE-2014-4609",
    "CVE-2014-4610"
  );
  script_bugtraq_id(
    55355,
    59417,
    65560,
    66057,
    66060,
    68217,
    68219
  );
  script_osvdb_id(
    85276,
    85285,
    85287,
    89076,
    103125,
    103282,
    103447,
    108490
  );
  script_xref(name:"MDVSA", value:"2014:129");

  script_name(english:"Mandriva Linux Security Advisory : ffmpeg (MDVSA-2014:129)");
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

Multiple unspecified vulnerabilities in libavcodec/wmalosslessdec.c in
FFmpeg before 0.11 have unknown impact and attack vectors related to
(1) size of mclms arrays, (2) a get_bits(0) in decode_ac_filter, and
(3) too many bits in decode_channel_residues(). (CVE-2012-2795).

libavcodec/wmalosslessdec.c in FFmpeg before 2.1.4 uses an incorrect
data-structure size for certain coefficients, which allows remote
attackers to cause a denial of service (memory corruption) or possibly
have unspecified other impact via crafted WMA data (CVE-2014-2098).

The msrle_decode_frame function in libavcodec/msrle.c in FFmpeg before
2.1.4 does not properly calculate line sizes, which allows remote
attackers to cause a denial of service (out-of-bounds array access) or
possibly have unspecified other impact via crafted Microsoft RLE video
data (CVE-2014-2099).

The mpegts_write_pmt function in the MPEG2 transport stream (aka DVB)
muxer (libavformat/mpegtsenc.c) in FFmpeg, possibly 2.1 and earlier,
allows remote attackers to have unspecified impact and vectors, which
trigger an out-of-bounds write (CVE-2014-2263).

A use-after-free vulnerability in FFmpeg before 1.1.9 involving seek
operations on video data could allow remote attackers to cause a
denial of service (CVE-2012-5150).

An integer overflow can occur when processing any variant of a literal
run in the av_lzo1x_decode function (CVE-2014-4609, CVE-2014-4610).

The updated packages have been upgraded to the 0.10.14 version which
is not vulnerable to these issues."
  );
  # http://blog.securitymouse.com/2014/06/raising-lazarus-20-year-old-bug-that.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76546f97"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/oss-sec/2014/q2/668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openwall.com/lists/oss-security/2014/06/26/22"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.ffmpeg.org/security.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"ffmpeg-0.10.14-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64avcodec53-0.10.14-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64avfilter2-0.10.14-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64avformat53-0.10.14-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64avutil51-0.10.14-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64ffmpeg-devel-0.10.14-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64ffmpeg-static-devel-0.10.14-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64postproc52-0.10.14-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64swresample0-0.10.14-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64swscaler2-0.10.14-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
