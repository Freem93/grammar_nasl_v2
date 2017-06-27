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
# Mandriva Linux Security Advisory MDVA-2011:032.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(56159);
  script_version("$Revision: 1.3 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:10 $");

  script_name(english:"MDVA-2011:032 : kdepim4");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"It was discovered that kmail crashed sometimes when deleting mail due
to a broken patch for nepomuk support.

The updated packages have been patched to correct this issue.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2011:032");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/09");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/12");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

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

if (rpm_check(reference:"akonadiconsole-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"akregator-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"blogilo-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"kaddressbook-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"kalarm-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"kdepim4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"kdepim4-core-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"kdepim4-devel-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"kdepim4-kresources-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"kdepim4-wizards-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"kjots-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"kleopatra-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"kmail-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"kmailcvt-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"knode-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"knotes-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"kontact-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"korganizer-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"ksendemail-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"ktimetracker-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libakonadi-kcal_next4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libakonadi-next4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libakregatorinterfaces4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libakregatorprivate4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libgwsoap4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkabc_groupdav4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkabc_groupwise4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkabckolab4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkabc_slox4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkaddressbookprivate4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkalarm_calendar4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkalarm_resources4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkcal_groupdav4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkcal_groupwise4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkcalkolab4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkcal_resourceblog4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkcal_resourceremote4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkcal_slox4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkdepim4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkgroupwarebase4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkgroupwaredav4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkleo4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkmailprivate4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libknodecommon4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libknoteskolab4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkontactprivate4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkorganizer_calendar4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkorganizer_core4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkorganizer_eventviewer4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkorganizer_interfaces4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkorganizerprivate4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkorg_stdprinting4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkpgp4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libksieve4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libkslox4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libmessagecore4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libmessagelist4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libmessageviewer0-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libmimelib4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"akonadiconsole-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"akregator-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"blogilo-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"kaddressbook-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"kalarm-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"kdepim4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"kdepim4-core-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"kdepim4-devel-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"kdepim4-kresources-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"kdepim4-wizards-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"kjots-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"kleopatra-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"kmail-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"kmailcvt-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"knode-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"knotes-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"kontact-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"korganizer-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"ksendemail-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"ktimetracker-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64akonadi-kcal_next4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64akonadi-next4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64akregatorinterfaces4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64akregatorprivate4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64gwsoap4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64kabc_groupdav4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64kabc_groupwise4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64kabckolab4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64kabc_slox4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64kaddressbookprivate4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64kalarm_calendar4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64kalarm_resources4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64kcal_groupdav4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64kcal_groupwise4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64kcalkolab4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64kcal_resourceblog4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64kcal_resourceremote4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64kcal_slox4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64kdepim4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64kgroupwarebase4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64kgroupwaredav4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64kleo4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64kmailprivate4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64knodecommon4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64knoteskolab4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64kontactprivate4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64korganizer_calendar4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64korganizer_core4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64korganizer_eventviewer4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64korganizer_interfaces4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64korganizerprivate4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64korg_stdprinting4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64kpgp4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64ksieve4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64kslox4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64messagecore4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64messagelist4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64messageviewer0-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64mimelib4-4.4.9-0.3mdv2010.2", release:"MDK2010.1", cpu:"x86_64", yank:"mdv")) flag++;


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
