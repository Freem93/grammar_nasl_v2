#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:142. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66154);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/01/14 15:43:29 $");

  script_cve_id("CVE-2013-0255", "CVE-2013-1899", "CVE-2013-1900", "CVE-2013-1901");
  script_bugtraq_id(57844, 58876, 58878, 58879);
  script_xref(name:"MDVSA", value:"2013:142");

  script_name(english:"Mandriva Linux Security Advisory : postgresql (MDVSA-2013:142)");
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
"Multiple vulnerabilities has been discovered and corrected in
postgresql :

PostgreSQL 9.2.x before 9.2.3, 9.1.x before 9.1.8, 9.0.x before
9.0.12, 8.4.x before 8.4.16, and 8.3.x before 8.3.23 does not properly
declare the enum_recv function in backend/utils/adt/enum.c, which
causes it to be invoked with incorrect arguments and allows remote
authenticated users to cause a denial of service (server crash) or
read sensitive process memory via a crafted SQL command, which
triggers an array index error and an out-of-bounds read
(CVE-2013-0255).

Argument injection vulnerability in PostgreSQL 9.2.x before 9.2.4,
9.1.x before 9.1.9, and 9.0.x before 9.0.13 allows remote attackers to
cause a denial of service (file corruption), and allows remote
authenticated users to modify configuration settings and execute
arbitrary code, via a connection request using a database name that
begins with a - (hyphen) (CVE-2013-1899).

PostgreSQL 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before
9.0.13, and 8.4.x before 8.4.17, when using OpenSSL, generates
insufficiently random numbers, which might allow remote authenticated
users to have an unspecified impact via vectors related to the
contrib/pgcrypto functions. (CVE-2013-1900).

PostgreSQL 9.2.x before 9.2.4 and 9.1.x before 9.1.9 does not properly
check REPLICATION privileges, which allows remote authenticated users
to bypass intended backup restrictions by calling the (1)
pg_start_backup or (2) pg_stop_backup functions (CVE-2013-1901).

This advisory provides the latest versions of PostgreSQL that is not
vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/9.2/static/release-9-2-3.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.postgresql.org/docs/9.2/static/release-9-2-4.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ecpg9.2_6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64pq9.2_5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.2-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.2-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.2-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.2-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.2-plpgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.2-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.2-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:postgresql9.2-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64ecpg9.2_6-9.2.4-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64pq9.2_5-9.2.4-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"postgresql9.2-9.2.4-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"postgresql9.2-contrib-9.2.4-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"postgresql9.2-devel-9.2.4-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"postgresql9.2-docs-9.2.4-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"postgresql9.2-pl-9.2.4-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"postgresql9.2-plperl-9.2.4-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"postgresql9.2-plpgsql-9.2.4-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"postgresql9.2-plpython-9.2.4-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"postgresql9.2-pltcl-9.2.4-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"postgresql9.2-server-9.2.4-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
