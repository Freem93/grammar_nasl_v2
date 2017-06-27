#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:033. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(36963);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/03/30 13:45:23 $");

  script_cve_id("CVE-2007-6183");
  script_bugtraq_id(26616);
  script_xref(name:"MDVSA", value:"2008:033");

  script_name(english:"Mandriva Linux Security Advisory : ruby-gnome2 (MDVSA-2008:033)");
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
"A format string vulnerability in Ruby-GNOME 2 0.16.0, and SVN versions
before 20071127, allows context-dependent attackers to execute
arbitrary code via format string specifiers in the message parameter.

The updated packages have been patched to prevent this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-atk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-gconf2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-gdkpixbuf2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-gnome2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-gnomecanvas2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-gnomeprint2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-gnomeprintui2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-gnomevfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-gtkglext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-gtkhtml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-gtkmozembed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-gtksourceview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-libart2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-libglade2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-panelapplet2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-pango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-rsvg2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ruby-vte");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.1", reference:"ruby-atk-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-gconf2-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-gdkpixbuf2-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-glib2-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-gnome2-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-gnome2-devel-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-gnomecanvas2-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-gnomeprint2-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-gnomeprintui2-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-gnomevfs2-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-gtk2-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-gtkglext-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-gtkhtml2-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-gtkmozembed-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-gtksourceview-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-libart2-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-libglade2-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-panelapplet2-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-pango-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-poppler-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-rsvg2-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2007.1", reference:"ruby-vte-0.16.0-2.1mdv2007.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.0", reference:"ruby-atk-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-gconf2-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-gdkpixbuf2-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-glib2-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-gnome2-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-gnome2-devel-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-gnomecanvas2-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-gnomeprint2-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-gnomeprintui2-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-gnomevfs2-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-gtk2-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-gtkglext-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-gtkhtml2-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-gtkmozembed-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-gtksourceview-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-libart2-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-libglade2-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-panelapplet2-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-pango-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-poppler-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-rsvg2-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"ruby-vte-0.16.0-3.1mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
