#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:184. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20043);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/31 23:51:58 $");

  script_cve_id("CVE-2005-2960", "CVE-2005-3137");
  script_xref(name:"MDKSA", value:"2005:184");

  script_name(english:"Mandrake Linux Security Advisory : cfengine (MDKSA-2005:184)");
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
"Javier Fern&aacute;ndez-Sanguino Pe&ntilde;a discovered several
insecure temporary file uses in cfengine <= 1.6.5 and <= 2.1.16 which
allows local users to overwrite arbitrary files via a symlink attack
on temporary files used by vicf.in. (CVE-2005-2960)

In addition, Javier discovered the cfmailfilter and cfcron.in files
for cfengine <= 1.6.5 allow local users to overwrite arbitrary files
via a symlink attack on temporary files (CVE-2005-3137)

The updated packages have been patched to address this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cfengine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cfengine-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cfengine-cfagent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cfengine-cfenvd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cfengine-cfexecd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cfengine-cfservd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.1", reference:"cfengine-1.6.5-4.3.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"cfengine-2.1.12-7.2.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"cfengine-cfservd-2.1.12-7.2.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", reference:"cfengine-base-2.1.15-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"cfengine-cfagent-2.1.15-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"cfengine-cfenvd-2.1.15-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"cfengine-cfexecd-2.1.15-2.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"cfengine-cfservd-2.1.15-2.2.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
