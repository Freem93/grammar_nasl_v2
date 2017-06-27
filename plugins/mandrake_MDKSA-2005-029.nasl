#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:029. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(16302);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:51:56 $");

  script_cve_id("CVE-2005-0069");
  script_xref(name:"MDKSA", value:"2005:029");

  script_name(english:"Mandrake Linux Security Advisory : vim (MDKSA-2005:029)");
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
"Javier Fernandez-Sanguino Pena discovered two vulnerabilities in
scripts included with the vim editor. The two scripts, 'tcltags' and
'vimspell.sh' created temporary files in an insecure manner which
could allow a malicious user to execute a symbolic link attack or to
create, or overwrite, arbitrary files with the privileges of the user
invoking the scripts.

The updated packages are patched to prevent this problem."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vim-X11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vim-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/03");
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
if (rpm_check(release:"MDK10.0", reference:"vim-X11-6.2-14.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"vim-common-6.2-14.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"vim-enhanced-6.2-14.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"vim-minimal-6.2-14.3.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"vim-X11-6.3-5.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"vim-common-6.3-5.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"vim-enhanced-6.3-5.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"vim-minimal-6.3-5.3.101mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
