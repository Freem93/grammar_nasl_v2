#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:031. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(72529);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/04/26 04:29:32 $");

  script_cve_id("CVE-2014-1475", "CVE-2014-1476");
  script_bugtraq_id(64973);
  script_xref(name:"MDVSA", value:"2014:031");

  script_name(english:"Mandriva Linux Security Advisory : drupal (MDVSA-2014:031)");
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
"Multiple security issues was identified and fixed in drupal :

The OpenID module in Drupal 6.x before 6.30 and 7.x before 7.26 allows
remote OpenID users to authenticate as other users via unspecified
vectors (CVE-2014-1475).

The Taxonomy module in Drupal 7.x before 7.26, when upgraded from an
earlier version of Drupal, does not properly restrict access to
unpublished content, which allows remote authenticated users to obtain
sensitive information via a listing page (CVE-2014-1476).

The updated packages has been upgraded to the 7.26 version which is
unaffected by these security flaws."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://drupal.org/SA-CORE-2014-001"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drupal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drupal-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drupal-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:drupal-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", reference:"drupal-7.26-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"drupal-mysql-7.26-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"drupal-postgresql-7.26-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"drupal-sqlite-7.26-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
