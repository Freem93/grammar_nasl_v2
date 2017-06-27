#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:095. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14077);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/05/31 23:47:34 $");

  script_cve_id("CVE-2003-0831");
  script_xref(name:"MDKSA", value:"2003:095-1");

  script_name(english:"Mandrake Linux Security Advisory : proftpd (MDKSA-2003:095-1)");
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
"A vulnerability was discovered by X-Force Research at ISS in ProFTPD's
handling of ASCII translation. An attacker, by downloading a carefully
crafted file, can remotely exploit this bug to create a root shell.

The ProFTPD team encourages all users to upgrade to version 1.2.7 or
higher. The problematic code first appeared in ProFTPD 1.2.7rc1, and
the provided packages are all patched by the ProFTPD team to protect
against this vulnerability.

Update :

The previous update had a bug where the new packages would terminate
with a SIGNAL 11 when the command 'NLST -alL' was performed in certain
cases, such as if the size of the output of the command was greater
than 1024 bytes.

These updated packages have a fix applied to prevent this crash."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.proftpd.org/show_bug.cgi?id=2194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://xforce.iss.net/xforce/alerts/id/154"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected proftpd and / or proftpd-anonymous packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-anonymous");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"proftpd-1.2.8-1.2.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", cpu:"i386", reference:"proftpd-anonymous-1.2.8-1.2.91mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", reference:"proftpd-1.2.8-5.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"proftpd-anonymous-1.2.8-5.2.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
