#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:118. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14100);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/31 23:47:34 $");

  script_cve_id("CVE-2003-0690");
  script_xref(name:"MDKSA", value:"2003:118");

  script_name(english:"Mandrake Linux Security Advisory : XFree86 (MDKSA-2003:118)");
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
"A vulnerability was discovered in the XDM display manager that ships
with XFree86. XDM does not check for successful completion of the
pam_setcred() call and in the case of error conditions in the
installed PAM modules, XDM may grant local root access to any user
with valid login credentials. It has been reported that a certain
configuration of the MIT pam_krb5 module can result in a failing
pam_setcred() call which leaves the session alive and would provide
root access to any regular user. It is also possible that this
vulnerability can likewise be exploited with other PAM modules in a
similar manner.

A backported patch from XFree86 4.3 that corrects this vulnerability
has been applied to these updated packages."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:X11R6-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86-100dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86-75dpi-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86-cyrillic-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86-glide-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86-static-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:XFree86-xfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xfree86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xfree86-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64xfree86-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxfree86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxfree86-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libxfree86-static-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
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
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"X11R6-contrib-4.2.1-3.2.90mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"XFree86-4.2.1-3.2.90mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"XFree86-100dpi-fonts-4.2.1-3.2.90mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"XFree86-75dpi-fonts-4.2.1-3.2.90mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"XFree86-Xnest-4.2.1-3.2.90mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"XFree86-Xvfb-4.2.1-3.2.90mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"XFree86-cyrillic-fonts-4.2.1-3.2.90mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"XFree86-devel-4.2.1-3.2.90mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"XFree86-doc-4.2.1-3.2.90mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"XFree86-glide-module-4.2.1-3.2.90mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"XFree86-libs-4.2.1-3.2.90mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"XFree86-server-4.2.1-3.2.90mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"XFree86-static-libs-4.2.1-3.2.90mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"XFree86-xfs-4.2.1-3.2.90mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"X11R6-contrib-4.3-8.4.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"XFree86-4.3-8.4.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"XFree86-100dpi-fonts-4.3-8.4.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"XFree86-75dpi-fonts-4.3-8.4.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"XFree86-Xnest-4.3-8.4.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"XFree86-Xvfb-4.3-8.4.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"XFree86-cyrillic-fonts-4.3-8.4.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"XFree86-devel-4.3-8.4.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"XFree86-doc-4.3-8.4.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"XFree86-glide-module-4.3-8.4.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"XFree86-libs-4.3-8.4.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"XFree86-server-4.3-8.4.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"XFree86-static-libs-4.3-8.4.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"XFree86-xfs-4.3-8.4.91mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"X11R6-contrib-4.3-24.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"XFree86-4.3-24.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"XFree86-100dpi-fonts-4.3-24.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"XFree86-75dpi-fonts-4.3-24.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"XFree86-Xnest-4.3-24.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"XFree86-Xvfb-4.3-24.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"XFree86-cyrillic-fonts-4.3-24.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"XFree86-doc-4.3-24.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"XFree86-glide-module-4.3-24.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"XFree86-server-4.3-24.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"XFree86-xfs-4.3-24.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64xfree86-4.3-24.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64xfree86-devel-4.3-24.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"lib64xfree86-static-devel-4.3-24.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libxfree86-4.3-24.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libxfree86-devel-4.3-24.1.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"i386", reference:"libxfree86-static-devel-4.3-24.1.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
