#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:157. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(16038);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/06/02 23:43:55 $");

  script_cve_id("CVE-2000-0174", "CVE-2004-1285", "CVE-2004-1309", "CVE-2004-1310", "CVE-2004-1311");
  script_xref(name:"MDKSA", value:"2004:157");

  script_name(english:"Mandrake Linux Security Advisory : mplayer (MDKSA-2004:157)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A number of vulnerabilities were discovered in the MPlayer program by
iDEFENSE, Ariel Berkman, and the MPlayer development team. These
vulnerabilities include potential heap overflows in Real RTSP and pnm
streaming code, stack overflows in MMST streaming code, and multiple
buffer overflows in the BMP demuxer and mp3lib code.

The updated packages have been patched to prevent these problems."
  );
  # http://www.idefense.com/application/poi/display?id=166&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4c7dac8f"
  );
  # http://www.idefense.com/application/poi/display?id=167&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12ef3169"
  );
  # http://www.idefense.com/application/poi/display?id=168&type=vulnerabilities
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cdbcba84"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64postproc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64postproc0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libdha0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libdha1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpostproc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpostproc0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mencoder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mplayer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mplayer-gui");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64postproc0-1.0-0.pre3.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64postproc0-devel-1.0-0.pre3.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libdha0.1-1.0-0.pre3.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libpostproc0-1.0-0.pre3.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libpostproc0-devel-1.0-0.pre3.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"mencoder-1.0-0.pre3.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"mplayer-1.0-0.pre3.14.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"mplayer-gui-1.0-0.pre3.14.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libdha1.0-1.0-0.pre5.7.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libpostproc0-1.0-0.pre5.7.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libpostproc0-devel-1.0-0.pre5.7.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"mencoder-1.0-0.pre5.7.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"mplayer-1.0-0.pre5.7.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"mplayer-gui-1.0-0.pre5.7.101mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
