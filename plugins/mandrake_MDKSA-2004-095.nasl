#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:095. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14751);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/31 23:47:35 $");

  script_cve_id("CVE-2004-0753", "CVE-2004-0782", "CVE-2004-0783", "CVE-2004-0788");
  script_xref(name:"MDKSA", value:"2004:095-1");

  script_name(english:"Mandrake Linux Security Advisory : gdk-pixbuf/gtk+2 (MDKSA-2004:095-1)");
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
"A vulnerability was found in the gdk-pixbug bmp loader where a bad BMP
image could send the bmp loader into an infinite loop (CVE-2004-0753).

Chris Evans found a heap-based overflow and a stack-based overflow in
the xpm loader of gdk-pixbuf (CVE-2004-0782 and CVE-2004-0783).

Chris Evans also discovered an integer overflow in the ico loader of
gdk-pixbuf (CVE-2004-0788).

All four problems have been corrected in these updated packages.

Update :

The previous package had an incorrect patch applied that would cause
some problems with other programs. The updated packages have the
correct patch applied.

As well, patched gtk+2 packages, which also contain gdk-pixbuf, are
now provided."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gdk-pixbuf-loaders");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gtk+2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gdk-pixbuf-gnomecanvas1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gdk-pixbuf-xlib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gdk-pixbuf2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gdk-pixbuf2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gdk_pixbuf2.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gdk_pixbuf2.0_0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gtk+-linuxfb-2.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gtk+-linuxfb-2.0_0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gtk+-x11-2.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gtk+2.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gtk+2.0_0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgdk-pixbuf-gnomecanvas1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgdk-pixbuf-xlib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgdk-pixbuf2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgdk-pixbuf2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgdk_pixbuf2.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgdk_pixbuf2.0_0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgtk+-linuxfb-2.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgtk+-linuxfb-2.0_0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgtk+-x11-2.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgtk+2.0_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgtk+2.0_0-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/16");
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
if (rpm_check(release:"MDK10.0", reference:"gdk-pixbuf-loaders-0.22.0-2.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"gtk+2.0-2.2.4-10.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64gdk-pixbuf-gnomecanvas1-0.22.0-2.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64gdk-pixbuf-xlib2-0.22.0-2.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64gdk-pixbuf2-0.22.0-2.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64gdk-pixbuf2-devel-0.22.0-2.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64gdk_pixbuf2.0_0-2.2.4-10.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64gdk_pixbuf2.0_0-devel-2.2.4-10.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64gtk+-linuxfb-2.0_0-2.2.4-10.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64gtk+-linuxfb-2.0_0-devel-2.2.4-10.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64gtk+-x11-2.0_0-2.2.4-10.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64gtk+2.0_0-2.2.4-10.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64gtk+2.0_0-devel-2.2.4-10.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libgdk-pixbuf-gnomecanvas1-0.22.0-2.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libgdk-pixbuf-xlib2-0.22.0-2.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libgdk-pixbuf2-0.22.0-2.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libgdk-pixbuf2-devel-0.22.0-2.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libgdk_pixbuf2.0_0-2.2.4-10.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libgdk_pixbuf2.0_0-devel-2.2.4-10.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libgtk+-linuxfb-2.0_0-2.2.4-10.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libgtk+-linuxfb-2.0_0-devel-2.2.4-10.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libgtk+-x11-2.0_0-2.2.4-10.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libgtk+2.0_0-2.2.4-10.1.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libgtk+2.0_0-devel-2.2.4-10.1.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"gdk-pixbuf-loaders-0.22.0-2.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"gtk+2.0-2.2.4-2.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64gdk-pixbuf-gnomecanvas1-0.22.0-2.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64gdk-pixbuf-xlib2-0.22.0-2.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64gdk-pixbuf2-0.22.0-2.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64gdk-pixbuf2-devel-0.22.0-2.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64gdk_pixbuf2.0_0-2.2.4-2.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64gdk_pixbuf2.0_0-devel-2.2.4-2.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64gtk+-linuxfb-2.0_0-2.2.4-2.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64gtk+-linuxfb-2.0_0-devel-2.2.4-2.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64gtk+-x11-2.0_0-2.2.4-2.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64gtk+2.0_0-2.2.4-2.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64gtk+2.0_0-devel-2.2.4-2.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libgdk-pixbuf-gnomecanvas1-0.22.0-2.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libgdk-pixbuf-xlib2-0.22.0-2.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libgdk-pixbuf2-0.22.0-2.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libgdk-pixbuf2-devel-0.22.0-2.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libgdk_pixbuf2.0_0-2.2.4-2.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libgdk_pixbuf2.0_0-devel-2.2.4-2.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libgtk+-linuxfb-2.0_0-2.2.4-2.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libgtk+-linuxfb-2.0_0-devel-2.2.4-2.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libgtk+-x11-2.0_0-2.2.4-2.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libgtk+2.0_0-2.2.4-2.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libgtk+2.0_0-devel-2.2.4-2.1.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
