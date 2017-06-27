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
# Mandriva Linux Security Advisory MDVA-2010:146.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(46262);
  script_version("$Revision: 1.7 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:09 $");

  script_name(english:"MDVA-2010:146 : mysql");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"A problem was discovered in the mysqld init script which under
certain circumstances could cause the service to exit too quickly,
giving the [ OK ] status and before the mysql server was really
started and bound to the mysql socket or IP address. This caused a
problem for products like Pulse2. The corrected packages solves this
problem.

Packages for 2008.0 and 2009.0 are provided due to the Extended
Maintenance Program for those products.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2010:146");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/07");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/05/10");
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

if (rpm_check(reference:"libmysql15-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libmysql-devel-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libmysql-static-devel-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-bench-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-client-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-common-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-max-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-ndb-extra-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-ndb-management-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-ndb-storage-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-ndb-tools-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"lib64mysql15-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64mysql-devel-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64mysql-static-devel-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-bench-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-client-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-common-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-max-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-ndb-extra-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-ndb-management-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-ndb-storage-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-ndb-tools-5.0.45-8.5mdv2008.0", release:"MDK2008.0", cpu:"x86_64", yank:"mdv")) flag++;

if (rpm_check(reference:"libmysql15-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libmysql-devel-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libmysql-static-devel-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-bench-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-client-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-common-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-doc-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-max-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-ndb-extra-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-ndb-management-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-ndb-storage-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-ndb-tools-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"lib64mysql15-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64mysql-devel-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64mysql-static-devel-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-bench-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-client-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-common-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-doc-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-max-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-ndb-extra-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-ndb-management-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-ndb-storage-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"mysql-ndb-tools-5.0.89-0.2mdv2009.0", release:"MDK2009.0", cpu:"x86_64", yank:"mdv")) flag++;


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
