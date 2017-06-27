#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:031. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(16360);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/08/17 14:24:38 $");

  script_cve_id("CVE-2004-0452", "CVE-2004-0976", "CVE-2005-0155", "CVE-2005-0156");
  script_xref(name:"MDKSA", value:"2005:031");

  script_name(english:"Mandrake Linux Security Advisory : perl (MDKSA-2005:031)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jeroen van Wolffelaar discovered that the rmtree() function in the
perl File::Path module would remove directories in an insecure manner
which could lead to the removal of arbitrary files and directories via
a symlink attack (CVE-2004-0452).

Trustix developers discovered several insecure uses of temporary files
in many modules which could allow a local attacker to overwrite files
via symlink attacks (CVE-2004-0976).

'KF' discovered two vulnerabilities involving setuid-enabled perl
scripts. By setting the PERLIO_DEBUG environment variable and calling
an arbitrary setuid-root perl script, an attacker could overwrite
arbitrary files with perl debug messages (CVE-2005-0155). As well,
calling a setuid-root perl script with a very long path would cause a
buffer overflow if PERLIO_DEBUG was set, which could be exploited to
execute arbitrary files with root privileges (CVE-2005-0156).

The provided packages have been patched to resolve these problems."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", reference:"perl-5.8.3-5.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"perl-base-5.8.3-5.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"perl-devel-5.8.3-5.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"perl-doc-5.8.3-5.3.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"perl-5.8.5-3.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"perl-base-5.8.5-3.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"perl-devel-5.8.5-3.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"perl-doc-5.8.5-3.3.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"perl-5.8.1-0.RC4.3.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"perl-base-5.8.1-0.RC4.3.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"perl-devel-5.8.1-0.RC4.3.3.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"perl-doc-5.8.1-0.RC4.3.3.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
