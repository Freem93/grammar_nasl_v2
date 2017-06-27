#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:143. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(25685);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/06/01 00:01:20 $");

  script_cve_id("CVE-2007-2948");
  script_xref(name:"MDKSA", value:"2007:143");

  script_name(english:"Mandrake Linux Security Advisory : mplayer (MDKSA-2007:143)");
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
"Multiple stack-based buffer overflows in stream/stream_cddb.c in
MPlayer before 1.0rc1try3 allow remote attackers to execute arbitrary
code via a CDDB entry with a long (1) album title or (2) category.

Updated packages have been patched to prevent this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libdha1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mencoder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mplayer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mplayer-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mplayer-gui");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"libdha1.0-1.0-1.pre8.13.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"mencoder-1.0-1.pre8.13.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"mplayer-1.0-1.pre8.13.4mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"mplayer-gui-1.0-1.pre8.13.4mdv2007.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"libdha1.0-1.0-1.rc1.11.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mencoder-1.0-1.rc1.11.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mplayer-1.0-1.rc1.11.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mplayer-doc-1.0-1.rc1.11.2mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"mplayer-gui-1.0-1.rc1.11.2mdv2007.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
