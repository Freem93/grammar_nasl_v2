#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:098. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(46664);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/12/22 14:20:01 $");

  script_cve_id("CVE-2010-1000", "CVE-2010-1511");
  script_bugtraq_id(40141);
  script_xref(name:"MDVSA", value:"2010:098");

  script_name(english:"Mandriva Linux Security Advisory : kdenetwork4 (MDVSA-2010:098)");
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
"Multiple vulnerabilities has been discovered and fixed in kget
(kdenetwork4) :

Directory traversal vulnerability in KGet in KDE SC 4.0.0 through
4.4.3 allows remote attackers to create arbitrary files via directory
traversal sequences in the name attribute of a file element in a
metalink file (CVE-2010-1000).

KGet 2.4.2 in KDE SC 4.0.0 through 4.4.3 does not properly request
download confirmation from the user, which makes it easier for remote
attackers to overwrite arbitrary files via a crafted metalink file
(CVE-2010-1511).

Packages for 2009.0 are provided due to the Extended Maintenance
Program.

The corrected packages solves these problems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kde.org/info/security/advisory-20100513-1.txt"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kde4-filesharing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork4-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdenetwork4-kopete-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kdnssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kget");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kopete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kppp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kppp-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:krfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gadu_kopete1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64iris_kopete1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kgetcore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kopete4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kopete_oscar4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kopete_otr_shared1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kopete_videodevice4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kopeteaddaccountwizard1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kopetechatwindow_shared1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kopetecontactlist1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kopeteidentity1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kopeteprivacy1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kopetestatusmenu1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64krdccore1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64kyahoo1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64oscar1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgadu_kopete1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libiris_kopete1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkgetcore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkopete4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkopete_oscar4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkopete_otr_shared1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkopete_videodevice4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkopeteaddaccountwizard1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkopetechatwindow_shared1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkopetecontactlist1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkopeteidentity1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkopeteprivacy1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkopetestatusmenu1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkrdccore1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libkyahoo1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:liboscar1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.0", reference:"kde4-filesharing-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kdenetwork4-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kdenetwork4-core-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kdenetwork4-devel-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kdenetwork4-kopete-latex-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kdnssd-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kget-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kopete-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kppp-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"kppp-provider-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"krdc-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"krfb-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64gadu_kopete1-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64iris_kopete1-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64kgetcore4-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64kopete4-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64kopete_oscar4-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64kopete_otr_shared1-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64kopete_videodevice4-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64kopeteaddaccountwizard1-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64kopetechatwindow_shared1-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64kopeteidentity1-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64kopeteprivacy1-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64kopetestatusmenu1-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64kyahoo1-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64oscar1-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libgadu_kopete1-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libiris_kopete1-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libkgetcore4-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libkopete4-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libkopete_oscar4-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libkopete_otr_shared1-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libkopete_videodevice4-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libkopeteaddaccountwizard1-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libkopetechatwindow_shared1-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libkopeteidentity1-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libkopeteprivacy1-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libkopetestatusmenu1-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libkyahoo1-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"liboscar1-4.2.4-0.8mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", reference:"kde4-filesharing-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kdenetwork4-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kdenetwork4-core-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kdenetwork4-devel-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kdenetwork4-kopete-latex-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kdnssd-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kget-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kopete-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kppp-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"kppp-provider-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"krdc-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"krfb-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64gadu_kopete1-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64iris_kopete1-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64kgetcore4-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64kopete4-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64kopete_oscar4-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64kopete_otr_shared1-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64kopete_videodevice4-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64kopeteaddaccountwizard1-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64kopetechatwindow_shared1-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64kopeteidentity1-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64kopeteprivacy1-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64kopetestatusmenu1-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64kyahoo1-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64oscar1-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libgadu_kopete1-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libiris_kopete1-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libkgetcore4-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libkopete4-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libkopete_oscar4-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libkopete_otr_shared1-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libkopete_videodevice4-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libkopeteaddaccountwizard1-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libkopetechatwindow_shared1-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libkopeteidentity1-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libkopeteprivacy1-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libkopetestatusmenu1-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libkyahoo1-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"liboscar1-4.2.4-0.4mdv2009.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", reference:"kde4-filesharing-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kdenetwork4-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kdenetwork4-core-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kdenetwork4-devel-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kdenetwork4-kopete-latex-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kdnssd-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kget-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kopete-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kppp-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"kppp-provider-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"krdc-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"krfb-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kgetcore4-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kopete4-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kopete_oscar4-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kopete_otr_shared1-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kopete_videodevice4-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kopeteaddaccountwizard1-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kopetechatwindow_shared1-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kopetecontactlist1-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kopeteidentity1-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kopeteprivacy1-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kopetestatusmenu1-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64krdccore1-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64kyahoo1-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64oscar1-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkgetcore4-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkopete4-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkopete_oscar4-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkopete_otr_shared1-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkopete_videodevice4-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkopeteaddaccountwizard1-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkopetechatwindow_shared1-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkopetecontactlist1-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkopeteidentity1-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkopeteprivacy1-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkopetestatusmenu1-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkrdccore1-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libkyahoo1-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"liboscar1-4.3.5-0.5mdv2010.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
