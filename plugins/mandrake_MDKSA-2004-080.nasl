#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2004:080. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14329);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:47:35 $");

  script_cve_id("CVE-2004-0647");
  script_xref(name:"MDKSA", value:"2004:080");

  script_name(english:"Mandrake Linux Security Advisory : shorewall (MDKSA-2004:080)");
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
"The shorewall package has a vulnerability when creating temporary
files and directories, which could allow non-root users to overwrite
arbitrary files on the system. The updated packages are patched to fix
the problem.

As well, for Mandrakelinux 10.0, the updated packages have been fixed
to start shorewall after the network, rather than before.

After updating the package, if shorewall was previously running, you
may need to issue a 'service shorewall restart'."
  );
  # http://lists.shorewall.net/pipermail/shorewall-announce/2004-June/000385.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3206be45"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected shorewall and / or shorewall-doc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:shorewall");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:shorewall-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/22");
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
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"shorewall-2.0.1-3.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"shorewall-2.0.1-3.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"shorewall-doc-2.0.1-3.2.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"shorewall-doc-2.0.1-3.2.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.1", reference:"shorewall-1.3.14-3.1.91mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.1", reference:"shorewall-doc-1.3.14-3.1.91mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"shorewall-1.4.8-2.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"shorewall-1.4.8-2.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", cpu:"amd64", reference:"shorewall-doc-1.4.8-2.2.92mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK9.2", reference:"shorewall-doc-1.4.8-2.2.92mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
