#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:102. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(66114);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/11/25 11:41:40 $");

  script_cve_id("CVE-2012-3147", "CVE-2012-3158", "CVE-2012-4414", "CVE-2012-5611", "CVE-2012-5612", "CVE-2012-5615", "CVE-2012-5627");
  script_bugtraq_id(55498, 56017, 56022, 56766, 56768, 56769, 56837);
  script_xref(name:"MDVSA", value:"2013:102");
  script_xref(name:"MGASA", value:"2012-0244");
  script_xref(name:"MGASA", value:"2012-0341");
  script_xref(name:"MGASA", value:"2012-0349");
  script_xref(name:"MGASA", value:"2013-0019");
  script_xref(name:"MGASA", value:"2013-0046");

  script_name(english:"Mandriva Linux Security Advisory : mariadb (MDVSA-2013:102)");
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
"Updated mariadb packages includes fixes for the following security
vulnerabilities :

Unspecified vulnerability in the MySQL Server component in Oracle
MySQL 5.5.26 and earlier allows remote attackers to affect integrity
and availability, related to MySQL Client (CVE-2012-3147).

Unspecified vulnerability in the MySQL Server component in Oracle
MySQL 5.1.64 and earlier, and 5.5.26 and earlier, allows remote
attackers to affect confidentiality, integrity, and availability via
unknown vectors related to Protocol (CVE-2012-3158).

Multiple SQL injection vulnerabilities in the replication code in
Oracle MySQL possibly before 5.5.29, and MariaDB 5.1.x through 5.1.62,
5.2.x through 5.2.12, 5.3.x through 5.3.7, and 5.5.x through 5.5.25,
allow remote authenticated users to execute arbitrary SQL commands via
vectors related to the binary log. NOTE: as of 20130116, Oracle has
not commented on claims from a downstream vendor that the fix in MySQL
5.5.29 is incomplete (CVE-2012-4414).

Stack-based buffer overflow in the acl_get function in Oracle MySQL
5.5.19 and other versions through 5.5.28, and 5.1.53 and other
versions through 5.1.66, and MariaDB 5.5.2.x before 5.5.28a, 5.3.x
before 5.3.11, 5.2.x before 5.2.13 and 5.1.x before 5.1.66, allows
remote authenticated users to execute arbitrary code via a long
argument to the GRANT FILE command (CVE-2012-5611).

A buffer overflow that can cause a server crash or arbitrary code
execution (a variant of CVE-2012-5611)

Heap-based buffer overflow in Oracle MySQL 5.5.19 and other versions
through 5.5.28, and MariaDB 5.5.28a and possibly other versions,
allows remote authenticated users to cause a denial of service (memory
corruption and crash) and possibly execute arbitrary code, as
demonstrated using certain variations of the (1) USE, (2) SHOW TABLES,
(3) DESCRIBE, (4) SHOW FIELDS FROM, (5) SHOW COLUMNS FROM, (6) SHOW
INDEX FROM, (7) CREATE TABLE, (8) DROP TABLE, (9) ALTER TABLE, (10)
DELETE FROM, (11) UPDATE, and (12) SET PASSWORD commands
(CVE-2012-5612).

MySQL 5.5.19 and possibly other versions, and MariaDB 5.5.28a, 5.3.11,
5.2.13, 5.1.66, and possibly other versions, generates different error
messages with different time delays depending on whether a user name
exists, which allows remote attackers to enumerate valid usernames
(CVE-2012-5615). Be advised that for CVE-2012-5615 to be completely
closed, it's recommended to remove any anonymous logins. Previously,
such a user without access rights was added by default.

A vulnerability was found in the handling of password salt values in
MySQL. When a user logs into MySQL a salt value is generated that is
then used to prevent password guessing attacks (since the salt value
must be known in order to send a password). This salt value is created
at the start of a session and used for the entire session, once
authenticated an attacker can use the MySQL change_user command to
attempt to login as a different, as the salt value is known a password
guessing attack will be much more efficient (CVE-2012-5627).

in addition it fixes MDEV-4029 and rpl.rpl_mdev382 test from
mariadb-bench, and a problem preventing the feedback plugin from
working has been corrected."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.mageia.org/en/Support/Advisories/MGAA-2012-0135"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mariadb-embedded-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mariadb-embedded18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64mariadb18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mariadb-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mariadb-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mariadb-common-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mariadb-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mariadb-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mariadb-feedback");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mariadb-obsolete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mysql-MariaDB");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64mariadb-devel-5.5.25-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64mariadb-embedded-devel-5.5.25-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64mariadb-embedded18-5.5.25-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64mariadb18-5.5.25-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"mariadb-5.5.25-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"mariadb-bench-5.5.25-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"mariadb-client-5.5.25-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"mariadb-common-5.5.25-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"mariadb-common-core-5.5.25-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"mariadb-core-5.5.25-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"mariadb-extra-5.5.25-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"mariadb-feedback-5.5.25-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"mariadb-obsolete-5.5.25-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"mysql-MariaDB-5.5.25-1.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
