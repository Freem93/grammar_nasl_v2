#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:140. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(19897);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:51:57 $");

  script_cve_id("CVE-2005-2390");
  script_xref(name:"MDKSA", value:"2005:140");

  script_name(english:"Mandrake Linux Security Advisory : proftpd (MDKSA-2005:140)");
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
"Two format string vulnerabilities were discovered in ProFTPD. The
first exists when displaying a shutdown message containin the name of
the current directory. This could be exploited by a user who creates a
directory containing format specifiers and sets the directory as the
current directory when the shutdown message is being sent.

The second exists when displaying response messages to the cleint
using information retreived from a database using mod_sql. Note that
mod_sql support is not enabled by default, but the contrib source file
has been patched regardless.

The updated packages have been patched to correct these problems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/advisories/16181"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected proftpd and / or proftpd-anonymous packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-anonymous");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
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
if (rpm_check(release:"MDK10.0", reference:"proftpd-1.2.9-3.3.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"proftpd-anonymous-1.2.9-3.3.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"proftpd-1.2.10-2.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"proftpd-anonymous-1.2.10-2.1.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"proftpd-1.2.10-9.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"proftpd-anonymous-1.2.10-9.1.102mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
