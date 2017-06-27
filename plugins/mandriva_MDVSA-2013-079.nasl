#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:079. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(66093);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/03/14 13:55:51 $");

  script_cve_id(
    "CVE-2011-3937",
    "CVE-2012-0851",
    "CVE-2012-2772",
    "CVE-2012-2775",
    "CVE-2012-2776",
    "CVE-2012-2777",
    "CVE-2012-2779",
    "CVE-2012-2784",
    "CVE-2012-2786",
    "CVE-2012-2787",
    "CVE-2012-2788",
    "CVE-2012-2789",
    "CVE-2012-2790",
    "CVE-2012-2793",
    "CVE-2012-2794",
    "CVE-2012-2796",
    "CVE-2012-2798",
    "CVE-2012-2800",
    "CVE-2012-2801",
    "CVE-2012-2802"
  );
  script_bugtraq_id(
    51307,
    51720,
    55355
  );
  script_osvdb_id(
    78178,
    78634,
    85268,
    85269,
    85271,
    85272,
    85273,
    85275,
    85279,
    85280,
    85281,
    85282,
    85286,
    85288,
    85290,
    85292,
    85293,
    85295,
    85300
  );
  script_xref(name:"MDVSA", value:"2013:079");
  script_xref(name:"MGASA", value:"2012-0143");
  script_xref(name:"MGASA", value:"2012-0331");

  script_name(english:"Mandriva Linux Security Advisory : ffmpeg (MDVSA-2013:079)");
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

h264: Add check for invalid chroma_format_idc (CVE-2012-0851)

h263dec: Disallow width/height changing with frame threads
(CVE-2011-3937)

vc1dec: check that coded slice positions and interlacing match. This
fixes out of array writes (CVE-2012-2796)

alsdec: fix number of decoded samples in first sub-block in BGMC mode
(CVE-2012-2790)

cavsdec: check for changing w/h. Our decoder does not support changing
w/h (CVE-2012-2777, CVE-2012-2784)

indeo4: update AVCodecContext width/height on size change
(CVE-2012-2787)

avidec: use actually read size instead of requested size
(CVE-2012-2788)

wmaprodec: check num_vec_coeffs for validity (CVE-2012-2789)

lagarith: check count before writing zeros (CVE-2012-2793)

indeo3: fix out of cell write (CVE-2012-2776)

indeo5: check tile size in decode_mb_info\(\). This prevents writing
into a too small array if some parameters changed without the tile
being reallocated (CVE-2012-2794)

indeo5dec: Make sure we have had a valid gop header. This prevents
decoding happening on a half initialized context (CVE-2012-2779)

indeo4/5: check empty tile size in decode_mb_info\(\). This prevents
writing into a too small array if some parameters changed without the
tile being reallocated (CVE-2012-2800)

dfa: improve boundary checks in decode_dds1\(\) (CVE-2012-2798)

dfa: check that the caller set width/height properly (CVE-2012-2786)

avsdec: Set dimensions instead of relying on the demuxer. The decode
function assumes that the video will have those dimensions
(CVE-2012-2801)

ac3dec: ensure get_buffer\(\) gets a buffer for the correct number of
channels (CVE-2012-2802)

rv34: error out on size changes with frame threading (CVE-2012-2772)

alsdec: check opt_order. Fixes out of array write in quant_cof. Also
make sure no invalid opt_order stays in the context (CVE-2012-2775)

This updates ffmpeg to version 0.10.6 which contains the security
fixes above as well as other bug fixes."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"ffmpeg-0.10.6-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64avcodec53-0.10.6-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64avfilter2-0.10.6-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64avformat53-0.10.6-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64avutil51-0.10.6-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64ffmpeg-devel-0.10.6-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64ffmpeg-static-devel-0.10.6-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64postproc52-0.10.6-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64swresample0-0.10.6-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64swscaler2-0.10.6-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
