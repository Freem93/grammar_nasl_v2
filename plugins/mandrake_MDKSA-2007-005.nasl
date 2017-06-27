#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:005. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(24621);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/31 23:56:40 $");

  script_cve_id("CVE-2006-6101", "CVE-2006-6102", "CVE-2006-6103");
  script_xref(name:"MDKSA", value:"2007:005");

  script_name(english:"Mandrake Linux Security Advisory : xorg-x11 (MDKSA-2007:005)");
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
"Sean Larsson of iDefense Labs discovered several vulnerabilities in
X.Org/XFree86 :

Local exploitation of a memory corruption vulnerability in the
'ProcRenderAddGlyphs()' function in the X.Org and XFree86 X server
could allow an attacker to execute arbitrary code with privileges of
the X server, typically root. (CVE-2006-6101)

Local exploitation of a memory corruption vulnerability in the
'ProcDbeGetVisualInfo()' function in the X.Org and XFree86 X server
could allow an attacker to execute arbitrary code with privileges of
the X server, typically root. (CVE-2006-6102)

Local exploitation of a memory corruption vulnerability in the
'ProcDbeSwapBuffers()' function in the X.Org and XFree86 X server
could allow an attacker to execute arbitrary code with privileges of
the X server, typically root. (CVE-2006-6103)

Updated packages are patched to address these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xati");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xchips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xepson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xfake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xfbdev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xi810");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xmach64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xmga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xneomagic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xnvidia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xpm2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xprt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xr128");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xsdl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xsmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xvesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xvia");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/18");
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
if (rpm_check(release:"MDK2007.0", reference:"x11-server-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"x11-server-common-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"x11-server-devel-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"x11-server-xati-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"x11-server-xchips-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"x11-server-xdmx-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"x11-server-xephyr-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"x11-server-xepson-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"x11-server-xfake-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"x11-server-xfbdev-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"x11-server-xi810-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"x11-server-xmach64-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"x11-server-xmga-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"x11-server-xneomagic-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"x11-server-xnest-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"x11-server-xnvidia-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"x11-server-xorg-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"x11-server-xpm2-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"x11-server-xprt-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"x11-server-xr128-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"x11-server-xsdl-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"x11-server-xsmi-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"x11-server-xvesa-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", reference:"x11-server-xvfb-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.0", cpu:"i386", reference:"x11-server-xvia-1.1.1-11.2mdv2007.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
