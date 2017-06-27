#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:210. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(78718);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/10/29 10:51:44 $");

  script_cve_id("CVE-2014-6464", "CVE-2014-6469", "CVE-2014-6507", "CVE-2014-6555", "CVE-2014-6559");
  script_bugtraq_id(70446, 70451, 70487, 70530, 70550);
  script_xref(name:"MDVSA", value:"2014:210");

  script_name(english:"Mandriva Linux Security Advisory : mariadb (MDVSA-2014:210)");
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
mariadb :

Unspecified vulnerability in Oracle MySQL Server 5.5.39 and earlier
and 5.6.20 and earlier allows remote authenticated users to affect
availability via vectors related to SERVER:INNODB DML FOREIGN KEYS
(CVE-2014-6464).

Unspecified vulnerability in Oracle MySQL Server 5.5.39 and eariler
and 5.6.20 and earlier allows remote authenticated users to affect
availability via vectors related to SERVER:OPTIMIZER (CVE-2014-6469).

Unspecified vulnerability in Oracle MySQL Server 5.5.39 and earlier,
and 5.6.20 and earlier, allows remote authenticated users to affect
confidentiality, integrity, and availability via vectors related to
SERVER:DML (CVE-2014-6507).

Unspecified vulnerability in Oracle MySQL Server 5.5.39 and earlier
and 5.6.20 and earlier allows remote authenticated users to affect
confidentiality, integrity, and availability via vectors related to
SERVER:DML (CVE-2014-6555).

Unspecified vulnerability in Oracle MySQL Server 5.5.39 and earlier,
and 5.6.20 and earlier, allows remote attackers to affect
confidentiality via vectors related to C API SSL CERTIFICATE HANDLING
(CVE-2014-6559).

The updated packages have been upgraded to the 5.5.40 version which is
not vulnerable to these issues.

Additionally MariaDB 5.5.40 removed the bundled copy of jemalloc from
the source tarball and only builds with jemalloc if a system copy of
the jemalloc library is detecting during the build. This update
provides the jemalloc library packages to resolve this issue."
  );
  # http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6dcc7b47"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.mageia.org/show_bug.cgi?id=14389"
  );
  # https://mariadb.com/kb/en/mariadb/development/release-notes/mariadb-5540-release-notes/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1bfaae1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64jemalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64jemalloc1");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/29");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64jemalloc-devel-3.6.0-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64jemalloc1-3.6.0-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64mariadb-devel-5.5.40-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64mariadb-embedded-devel-5.5.40-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64mariadb-embedded18-5.5.40-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64mariadb18-5.5.40-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"mariadb-5.5.40-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"mariadb-bench-5.5.40-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"mariadb-client-5.5.40-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"mariadb-common-5.5.40-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"mariadb-common-core-5.5.40-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"mariadb-core-5.5.40-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"mariadb-extra-5.5.40-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"mariadb-feedback-5.5.40-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"mariadb-obsolete-5.5.40-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"mysql-MariaDB-5.5.40-1.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
