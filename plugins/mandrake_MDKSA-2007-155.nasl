#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:155. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(36699);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/06/01 00:01:20 $");

  script_cve_id("CVE-2007-1218");
  script_xref(name:"MDKSA", value:"2007:155");

  script_name(english:"Mandrake Linux Security Advisory : tcpdump (MDKSA-2007:155)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandrake Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Off-by-one buffer overflow in the parse_elements function in the
802.11 printer code (print-802_11.c) for tcpdump 3.9.5 and earlier
allows remote attackers to cause a denial of service (crash) via a
crafted 802.11 frame.

Updated packages have been patched to prevent this issue."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tcpdump package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119,189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tcpdump");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.1", reference:"tcpdump-3.9.5-1.2mdv2007.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
