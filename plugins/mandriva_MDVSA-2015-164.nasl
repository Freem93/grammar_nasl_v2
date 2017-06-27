#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:164. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82417);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/28 21:52:55 $");

  script_cve_id("CVE-2014-6271", "CVE-2014-6277", "CVE-2014-6278", "CVE-2014-7169", "CVE-2014-7186", "CVE-2014-7187");
  script_xref(name:"MDVSA", value:"2015:164");
  script_xref(name:"IAVA", value:"2014-A-0142");

  script_name(english:"Mandriva Linux Security Advisory : bash (MDVSA-2015:164)");
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
"Updated bash packages fix security vulnerability :

A flaw was found in the way Bash evaluated certain specially crafted
environment variables. An attacker could use this flaw to override or
bypass environment restrictions to execute shell commands. Certain
services and applications allow remote unauthenticated attackers to
provide environment variables, allowing them to exploit this issue
(CVE-2014-6271).

This vulnerability can be exposed and exploited through several other
pieces of software and should be considered highly critical. Please
refer to the RedHat Knowledge Base article and blog post for more
information.

It was found that the fix for CVE-2014-6271 was incomplete, and Bash
still allowed certain characters to be injected into other
environments via specially crafted environment variables. An attacker
could potentially use this flaw to override or bypass environment
restrictions to execute shell commands. Certain services and
applications allow remote unauthenticated attackers to provide
environment variables, allowing them to exploit this issue
(CVE-2014-7169).

Bash has been updated to version 4.2 patch level 50, which further
mitigates ShellShock-type vulnerabilities. Two such issues have
already been discovered (CVE-2014-6277, CVE-2014-6278).

See the RedHat article on the backward-incompatible changes introduced
by the latest patch, caused by adding prefixes and suffixes to the
variable names used for exporting functions. Note that the RedHat
article mentions these variable names will have parentheses '()' at
the end of their names, however, the latest upstream patch uses two
percent signs '%%' at the end instead.

Two other unrelated security issues in the parser have also been fixed
in this update (CVE-2014-7186, CVE-2014-7187).

All users and sysadmins are advised to update their bash package
immediately."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0388.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0393.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/1200223"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bash and / or bash-doc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:bash-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"bash-4.2-53.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"bash-doc-4.2-53.1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
