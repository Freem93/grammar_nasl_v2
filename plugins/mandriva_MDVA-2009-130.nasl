#%NASL_MIN_LEVEL 99999
# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a security fix.
#
# Disabled on 2012/09/06.
#

#
# (C) Tenable Network Security, Inc.
#
# This script was automatically generated from
# Mandriva Linux Security Advisory MDVA-2009:130.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(47943);
  script_version("$Revision: 1.6 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:07 $");

  script_name(english:"MDVA-2009:130 : evolution");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Evolution had several bugs like a hanging user interface when dealing
with virtual folders that have been fixed in this update.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2009:130");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/14");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/07/30");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a security fix.");


include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Mandrake/release")) exit(0, "The host is not running Mandrake Linux.");
if (!get_kb_item("Host/Mandrake/rpm-list")) exit(1, "Could not get the list of packages.");

flag = 0;

if (rpm_check(reference:"evolution-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"evolution-data-server-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"evolution-devel-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"evolution-exchange-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"evolution-mono-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"evolution-pilot-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"gtkhtml-3.14-3.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libcamel14-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libebackend0-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libebook9-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libecal7-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libedata-book2-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libedata-cal6-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libedataserver11-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libedataserver-devel-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libedataserverui8-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libegroupwise13-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libexchange-storage3-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libgdata1-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libgtkhtml-3.14_19-3.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libgtkhtml-3.14-devel-3.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"evolution-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"evolution-data-server-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"evolution-devel-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"evolution-exchange-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"evolution-mono-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"evolution-pilot-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"gtkhtml-3.14-3.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64camel14-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64ebackend0-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64ebook9-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64ecal7-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64edata-book2-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64edata-cal6-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64edataserver11-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64edataserver-devel-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64edataserverui8-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64egroupwise13-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64exchange-storage3-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64gdata1-2.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64gtkhtml-3.14_19-3.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64gtkhtml-3.14-devel-3.26.3-1.1mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else 
{
  exit(0, "The host is not affected.");
}
