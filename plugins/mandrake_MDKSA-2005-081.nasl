#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:081. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(18235);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:51:57 $");

  script_cve_id("CVE-2005-0605");
  script_xref(name:"MDKSA", value:"2005:081");

  script_name(english:"Mandrake Linux Security Advisory : XFree86 (MDKSA-2005:081)");
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
"The XPM library which is part of the XFree86/XOrg project is used by
several GUI applications to process XPM image files.

The XPM library which is part of the XFree86/XOrg project is used by
several GUI applications to process XPM image files.

An integer overflow flaw was found in libXPM, which is used by some
applications for loading of XPM images. An attacker could create a
malicious XPM file that would execute arbitrary code via a negative
bitmap_unit value if opened by a victim using an application linked to
the vulnerable library.

Updated packages are patched to correct all these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:X11R6-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86-cyrillic-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86-glide-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86-xfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xfree86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xfree86-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xfree86-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xorg-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xorg-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xorg-x11-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxfree86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxfree86-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxfree86-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxorg-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxorg-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxorg-x11-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11-Xprt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11-cyrillic-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11-glide-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11-xauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:xorg-x11-xfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", reference:"X11R6-contrib-4.3-32.4.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"XFree86-4.3-32.4.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"XFree86-100dpi-fonts-4.3-32.4.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"XFree86-75dpi-fonts-4.3-32.4.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"XFree86-Xnest-4.3-32.4.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"XFree86-Xvfb-4.3-32.4.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"XFree86-cyrillic-fonts-4.3-32.4.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"XFree86-doc-4.3-32.4.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"XFree86-glide-module-4.3-32.4.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"XFree86-server-4.3-32.4.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"XFree86-xfs-4.3-32.4.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64xfree86-4.3-32.4.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64xfree86-devel-4.3-32.4.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64xfree86-static-devel-4.3-32.4.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libxfree86-4.3-32.4.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libxfree86-devel-4.3-32.4.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libxfree86-static-devel-4.3-32.4.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"X11R6-contrib-6.7.0-4.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64xorg-x11-6.7.0-4.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64xorg-x11-devel-6.7.0-4.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"x86_64", reference:"lib64xorg-x11-static-devel-6.7.0-4.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libxorg-x11-6.7.0-4.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libxorg-x11-devel-6.7.0-4.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"libxorg-x11-static-devel-6.7.0-4.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xorg-x11-6.7.0-4.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xorg-x11-100dpi-fonts-6.7.0-4.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xorg-x11-75dpi-fonts-6.7.0-4.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xorg-x11-Xnest-6.7.0-4.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xorg-x11-Xvfb-6.7.0-4.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xorg-x11-cyrillic-fonts-6.7.0-4.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xorg-x11-doc-6.7.0-4.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"xorg-x11-glide-module-6.7.0-4.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xorg-x11-server-6.7.0-4.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"xorg-x11-xfs-6.7.0-4.3.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"X11R6-contrib-6.8.2-7.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64xorg-x11-6.8.2-7.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64xorg-x11-devel-6.8.2-7.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"x86_64", reference:"lib64xorg-x11-static-devel-6.8.2-7.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libxorg-x11-6.8.2-7.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libxorg-x11-devel-6.8.2-7.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"libxorg-x11-static-devel-6.8.2-7.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xorg-x11-6.8.2-7.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xorg-x11-100dpi-fonts-6.8.2-7.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xorg-x11-75dpi-fonts-6.8.2-7.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xorg-x11-Xdmx-6.8.2-7.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xorg-x11-Xnest-6.8.2-7.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xorg-x11-Xprt-6.8.2-7.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xorg-x11-Xvfb-6.8.2-7.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xorg-x11-cyrillic-fonts-6.8.2-7.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xorg-x11-doc-6.8.2-7.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", cpu:"i386", reference:"xorg-x11-glide-module-6.8.2-7.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xorg-x11-server-6.8.2-7.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xorg-x11-xauth-6.8.2-7.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"xorg-x11-xfs-6.8.2-7.1.102mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
