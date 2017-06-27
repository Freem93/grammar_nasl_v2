#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:116. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(38138);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/04/15 10:48:38 $");

  script_cve_id("CVE-2008-1377", "CVE-2008-1379", "CVE-2008-2360", "CVE-2008-2361", "CVE-2008-2362");
  script_xref(name:"MDVSA", value:"2008:116");

  script_name(english:"Mandriva Linux Security Advisory : x11-server (MDVSA-2008:116)");
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
"An input validation flaw was found in X.org's Security and Record
extensions. A malicious authorized client could exploit the issue to
cause a denial of service (crash) or possibly execute arbitrary code
with root privileges on the X.org server (CVE-2008-1377).

An input validation flaw was found in X.org's MIT-SHM extension. A
client connected to the X.org server could read arbitrary server
memory, resulting in the disclosure of sensitive data of other users
of the X.org server (CVE-2008-1379).

Multiple integer overflows were found in X.org's Render extension. A
malicious authorized client could exploit these issues to cause a
denial of service (crash) or possibly execute arbitrary code with root
privileges on the X.org server (CVE-2008-2360, CVE-2008-2361,
CVE-2008-2362).

In addition, this update corrects a problem that could cause memory
corruption or segfaults in the render code of the vnc server on
Mandriva Linux 2008.1

The updated packages have been patched to prevent these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189);

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xgl");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:x11-server-xvnc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.1", reference:"x11-server-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"x11-server-common-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"x11-server-devel-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"x11-server-xati-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"x11-server-xchips-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"x11-server-xdmx-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"x11-server-xephyr-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"x11-server-xepson-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"x11-server-xfake-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"x11-server-xfbdev-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"x11-server-xgl-0.0.1-0.20070105.4.4mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"x11-server-xi810-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"x11-server-xmach64-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"x11-server-xmga-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"x11-server-xneomagic-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"x11-server-xnest-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"x11-server-xnvidia-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"x11-server-xorg-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"x11-server-xpm2-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"x11-server-xprt-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"x11-server-xr128-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"x11-server-xsdl-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"x11-server-xsmi-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"x11-server-xvesa-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"x11-server-xvfb-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", cpu:"i386", reference:"x11-server-xvia-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"x11-server-xvnc-1.2.0-9.5mdv2007.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.0", reference:"x11-server-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"x11-server-common-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"x11-server-devel-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"x11-server-xati-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"x11-server-xchips-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"x11-server-xdmx-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"x11-server-xephyr-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"x11-server-xepson-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"x11-server-xfake-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"x11-server-xfbdev-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"x11-server-xgl-0.0.1-0.20070917.2.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"x11-server-xi810-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"x11-server-xmach64-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"x11-server-xmga-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"x11-server-xneomagic-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"x11-server-xnest-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"x11-server-xnvidia-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"x11-server-xorg-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"x11-server-xpm2-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"x11-server-xr128-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"x11-server-xsdl-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"x11-server-xsmi-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"x11-server-xvesa-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"x11-server-xvfb-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"x11-server-xvia-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"x11-server-xvnc-1.3.0.0-24.2mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.1", reference:"x11-server-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"x11-server-common-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"x11-server-devel-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"x11-server-xati-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"x11-server-xchips-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"x11-server-xephyr-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"x11-server-xepson-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"x11-server-xfake-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"x11-server-xfbdev-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"x11-server-xgl-0.0.1-0.20070917.2.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"x11-server-xi810-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"x11-server-xmach64-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"x11-server-xmga-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"x11-server-xnest-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"x11-server-xnvidia-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"x11-server-xorg-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"x11-server-xpm2-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"x11-server-xr128-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"x11-server-xsdl-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"x11-server-xsmi-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"x11-server-xvesa-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"x11-server-xvfb-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", cpu:"i386", reference:"x11-server-xvia-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"x11-server-xvnc-1.4.0.90-13.2mdv2008.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
