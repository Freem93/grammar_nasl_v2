#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:045. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(37405);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/28 21:39:22 $");

  script_cve_id("CVE-2008-0225", "CVE-2008-0238", "CVE-2008-0485", "CVE-2008-0486", "CVE-2008-0629", "CVE-2008-0630");
  script_xref(name:"MDVSA", value:"2008:045");

  script_name(english:"Mandriva Linux Security Advisory : mplayer (MDVSA-2008:045)");
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
"Heap-based buffer overflow in the rmff_dump_cont function in
input/libreal/rmff.c in xine-lib 1.1.9 and earlier allows remote
attackers to execute arbitrary code via the SDP Abstract attribute,
related to the rmff_dump_header function and related to disregarding
the max field. Although originally a xine-lib issue, also affects
MPlayer due to code similarity. (CVE-2008-0225)

Multiple heap-based buffer overflows in the rmff_dump_cont function in
input/libreal/rmff.c in xine-lib 1.1.9 allow remote attackers to
execute arbitrary code via the SDP (1) Title, (2) Author, or (3)
Copyright attribute, related to the rmff_dump_header function,
different vectors than CVE-2008-0225. Although originally a xine-lib
issue, also affects MPlayer due to code similarity. (CVE-2008-0238)

Array index error in libmpdemux/demux_mov.c in MPlayer 1.0 rc2 and
earlier might allow remote attackers to execute arbitrary code via a
QuickTime MOV file with a crafted stsc atom tag. (CVE-2008-0485)

Array index vulnerability in libmpdemux/demux_audio.c in MPlayer
1.0rc2 and SVN before r25917, and possibly earlier versions, as used
in Xine-lib 1.1.10, might allow remote attackers to execute arbitrary
code via a crafted FLAC tag, which triggers a buffer overflow.
(CVE-2008-0486)

Buffer overflow in stream_cddb.c in MPlayer 1.0rc2 and SVN before
r25824 allows remote user-assisted attackers to execute arbitrary code
via a CDDB database entry containing a long album title.
(CVE-2008-0629)

Buffer overflow in url.c in MPlayer 1.0rc2 and SVN before r25823
allows remote attackers to execute arbitrary code via a crafted URL
that prevents the IPv6 parsing code from setting a pointer to NULL,
which causes the buffer to be reused by the unescape code.
(CVE-2008-0630)

The updated packages have been patched to prevent these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libdha1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mencoder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mplayer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mplayer-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mplayer-gui");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libdha1.0-1.0-1.rc1.11.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mencoder-1.0-1.rc1.11.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mplayer-1.0-1.rc1.11.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mplayer-doc-1.0-1.rc1.11.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mplayer-gui-1.0-1.rc1.11.5mdv2007.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libdha1.0-1.0-1.rc1.20.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mencoder-1.0-1.rc1.20.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mplayer-1.0-1.rc1.20.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mplayer-doc-1.0-1.rc1.20.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"mplayer-gui-1.0-1.rc1.20.2mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
