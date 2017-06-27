# @DEPRECATED@
#
# This script has been deprecated as the associated update is not
# for a supported release of Mandrake / Mandriva Linux.
#
# Disabled on 2012/09/06.
#

#
# (C) Tenable Network Security, Inc.
#
# This script was automatically generated from
# Mandrake Linux Security Advisory MDKSA-2005:135.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(20422);
  script_version ("$Revision: 1.9 $"); 
  script_cvs_date("$Date: 2012/09/07 00:48:07 $");

  script_cve_id("CVE-2005-2097");

  script_name(english:"MDKSA-2005:135 : kdegraphics");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandrake host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the kpdf KDE PDF viewer was discovered. An
attacker could construct a malicious PDF file that would cause kpdf
to consume all available disk space in /tmp when opened.

The updated packages have been patched to correct this problem.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDKSA-2005:135");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/15");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}

# Deprecated.
exit(0, "The associated update is not currently for a supported release of Mandrake / Mandriva Linux.");


include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Mandrake/release")) exit(0, "The host is not running Mandrake Linux.");
if (!get_kb_item("Host/Mandrake/rpm-list")) exit(1, "Could not get the list of packages.");

flag = 0;

if (rpm_check(reference:"kdegraphics-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kdegraphics-common-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kdegraphics-kdvi-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kdegraphics-kfax-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kdegraphics-kghostview-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kdegraphics-kiconedit-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kdegraphics-kolourpaint-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kdegraphics-kooka-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kdegraphics-kpaint-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kdegraphics-kpdf-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kdegraphics-kpovmodeler-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kdegraphics-kruler-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kdegraphics-ksnapshot-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kdegraphics-ksvg-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kdegraphics-kuickshow-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kdegraphics-kview-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"kdegraphics-mrmlsearch-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libkdegraphics0-common-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libkdegraphics0-common-devel-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libkdegraphics0-kghostview-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libkdegraphics0-kghostview-devel-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libkdegraphics0-kooka-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libkdegraphics0-kooka-devel-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libkdegraphics0-kpovmodeler-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libkdegraphics0-kpovmodeler-devel-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libkdegraphics0-ksvg-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libkdegraphics0-ksvg-devel-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libkdegraphics0-kuickshow-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libkdegraphics0-kview-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libkdegraphics0-kview-devel-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;
if (rpm_check(reference:"libkdegraphics0-mrmlsearch-3.3.2-21.2.102mdk", release:"MDK10.2", cpu:"i386", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else 
{
  if (rpm_exists(rpm:"kdegraphics-", release:"MDK10.2"))
  {
    set_kb_item(name:"CVE-2005-2097", value:TRUE);
  }

  exit(0, "The host is not affected.");
}
