#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:050. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(52748);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/17 17:02:55 $");

  script_cve_id("CVE-2011-1091");
  script_bugtraq_id(46837);
  script_xref(name:"MDVSA", value:"2011:050");

  script_name(english:"Mandriva Linux Security Advisory : pidgin (MDVSA-2011:050)");
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
"Multiple vulnerabilities has been identified and fixed in pidgin :

It was discovered that libpurple versions prior to 2.7.10 do not
properly clear certain data structures used in libpurple/cipher.c
prior to freeing. An attacker could potentially extract partial
information from memory regions freed by libpurple.

The Yahoo protocol plugin in libpurple versions 2.6.0 through 2.7.10
do not properly handle malformed YMSG packets, leading to NULL pointer
dereferences and application crash (CVE-2011-1091).

Packages for 2009.0 are provided as of the Extended Maintenance
Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149 products_id=490

This update provides pidgin 2.7.11, which is not vulnerable to these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://pidgin.im/news/security/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.pidgin.im/news/security/?id=50"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64finch0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64purple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64purple0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libfinch0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpurple0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-bonjour");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-gevolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-meanwhile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-silc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-tcl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.0", reference:"finch-2.7.11-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64finch0-2.7.11-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64purple-devel-2.7.11-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64purple0-2.7.11-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libfinch0-2.7.11-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libpurple-devel-2.7.11-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libpurple0-2.7.11-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pidgin-2.7.11-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pidgin-bonjour-2.7.11-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pidgin-client-2.7.11-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pidgin-gevolution-2.7.11-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pidgin-i18n-2.7.11-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pidgin-meanwhile-2.7.11-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pidgin-perl-2.7.11-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pidgin-plugins-2.7.11-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pidgin-silc-2.7.11-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pidgin-tcl-2.7.11-0.2mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", reference:"finch-2.7.11-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64finch0-2.7.11-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64purple-devel-2.7.11-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"x86_64", reference:"lib64purple0-2.7.11-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libfinch0-2.7.11-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libpurple-devel-2.7.11-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", cpu:"i386", reference:"libpurple0-2.7.11-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"pidgin-2.7.11-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"pidgin-bonjour-2.7.11-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"pidgin-client-2.7.11-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"pidgin-i18n-2.7.11-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"pidgin-meanwhile-2.7.11-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"pidgin-perl-2.7.11-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"pidgin-plugins-2.7.11-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"pidgin-silc-2.7.11-0.2mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"pidgin-tcl-2.7.11-0.2mdv2010.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"finch-2.7.11-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64finch0-2.7.11-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64purple-devel-2.7.11-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64purple0-2.7.11-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libfinch0-2.7.11-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libpurple-devel-2.7.11-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libpurple0-2.7.11-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"pidgin-2.7.11-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"pidgin-bonjour-2.7.11-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"pidgin-client-2.7.11-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"pidgin-i18n-2.7.11-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"pidgin-meanwhile-2.7.11-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"pidgin-perl-2.7.11-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"pidgin-plugins-2.7.11-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"pidgin-silc-2.7.11-0.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"pidgin-tcl-2.7.11-0.2mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
