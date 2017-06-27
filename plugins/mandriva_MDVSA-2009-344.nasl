#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:344. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(43609);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/28 21:39:24 $");

  script_cve_id("CVE-2009-0663", "CVE-2009-1341");
  script_bugtraq_id(34755, 34757);
  script_xref(name:"MDVSA", value:"2009:344");

  script_name(english:"Mandriva Linux Security Advisory : perl-DBD-Pg (MDVSA-2009:344)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandriva Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities was discovered and corrected in perl-DBD-Pg :

Heap-based buffer overflow in the DBD::Pg module for Perl might allow
context-dependent attackers to execute arbitrary code via unspecified
input to an application that uses the getline and pg_getline functions
to read database rows.

Memory leak in the dequote_bytea function in quote.c in the DBD::Pg
(aka DBD-Pg or libdbd-pg-perl) module before 2.0.0 for Perl allows
context-dependent attackers to cause a denial of service (memory
consumption) by fetching data with BYTEA columns (CVE-2009-1341).

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers.

This update provides a fix for these vulnerabilities."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected perl-DBD-Pg package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-DBD-Pg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", reference:"perl-DBD-Pg-1.49-2.1mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
