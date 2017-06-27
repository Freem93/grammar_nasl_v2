#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:210. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20443);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/31 23:51:58 $");

  script_cve_id("CVE-2005-3183");
  script_xref(name:"MDKSA", value:"2005:210");

  script_name(english:"Mandrake Linux Security Advisory : w3c-libwww (MDKSA-2005:210)");
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
"Sam Varshavchik discovered the HTBoundary_put_block function in
HTBound.c for W3C libwww (w3c-libwww) allows remote servers to cause a
denial of service (segmentation fault) via a crafted
multipart/byteranges MIME message that triggers an out-of-bounds read.

The updated packages have been patched to address this issue."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected w3c-libwww, w3c-libwww-apps and / or
w3c-libwww-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:w3c-libwww");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:w3c-libwww-apps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:w3c-libwww-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.1", reference:"w3c-libwww-5.4.0-3.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"w3c-libwww-apps-5.4.0-3.1.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"w3c-libwww-devel-5.4.0-3.1.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"w3c-libwww-5.4.0-5.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"w3c-libwww-apps-5.4.0-5.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"w3c-libwww-devel-5.4.0-5.1.102mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK2006.0", reference:"w3c-libwww-5.4.0-5.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"w3c-libwww-apps-5.4.0-5.1.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"w3c-libwww-devel-5.4.0-5.1.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
