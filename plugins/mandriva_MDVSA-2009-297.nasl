#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:297. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(42809);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id("CVE-2008-3230", "CVE-2008-4869", "CVE-2009-0385");
  script_bugtraq_id(33502);
  script_xref(name:"MDVSA", value:"2009:297-1");

  script_name(english:"Mandriva Linux Security Advisory : ffmpeg (MDVSA-2009:297-1)");
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
"Vulnerabilities have been discovered and corrected in ffmpeg :

  - The ffmpeg lavf demuxer allows user-assisted attackers
    to cause a denial of service (application crash) via a
    crafted GIF file (CVE-2008-3230)

  - FFmpeg 0.4.9, as used by MPlayer, allows
    context-dependent attackers to cause a denial of service
    (memory consumption) via unknown vectors, aka a Tcp/udp
    memory leak. (CVE-2008-4869)

  - Integer signedness error in the fourxm_read_header
    function in libavformat/4xm.c in FFmpeg before revision
    16846 allows remote attackers to execute arbitrary code
    via a malformed 4X movie file with a large current_track
    value, which triggers a NULL pointer dereference
    (CVE-2009-0385)

The updated packages fix this issue.

Update :

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avformats51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64avutil49");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ffmpeg51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ffmpeg51-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ffmpeg51-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavformats51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libavutil49");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libffmpeg51");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libffmpeg51-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libffmpeg51-static-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", reference:"ffmpeg-0.4.9-3.pre1.8994.2.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64avformats51-0.4.9-3.pre1.8994.2.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64avutil49-0.4.9-3.pre1.8994.2.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64ffmpeg51-0.4.9-3.pre1.8994.2.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64ffmpeg51-devel-0.4.9-3.pre1.8994.2.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64ffmpeg51-static-devel-0.4.9-3.pre1.8994.2.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libavformats51-0.4.9-3.pre1.8994.2.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libavutil49-0.4.9-3.pre1.8994.2.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libffmpeg51-0.4.9-3.pre1.8994.2.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libffmpeg51-devel-0.4.9-3.pre1.8994.2.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libffmpeg51-static-devel-0.4.9-3.pre1.8994.2.3mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
