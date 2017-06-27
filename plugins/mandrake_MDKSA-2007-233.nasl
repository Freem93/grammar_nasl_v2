#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2007:233. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(28352);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/06/01 00:01:21 $");

  script_cve_id("CVE-2005-1229", "CVE-2007-4476");
  script_xref(name:"MDKSA", value:"2007:233");

  script_name(english:"Mandrake Linux Security Advisory : cpio (MDKSA-2007:233)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandrake Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Buffer overflow in the safer_name_suffix function in GNU cpio has
unspecified attack vectors and impact, resulting in a crashing stack.
This problem is originally found in tar, but affects cpio too, due to
similar code fragments. (CVE-2007-4476)

Directory traversal vulnerability in cpio 2.6 and earlier allows
remote attackers to write to arbitrary directories via a .. (dot dot)
in a cpio file. This is an old issue, affecting only Mandriva
Corporate Server 4 and Mandriva Linux 2007. (CVE-2005-1229)

Updated package fixes these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cpio package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cpio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.0", reference:"cpio-2.6-7.1mdv2007.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2007.1", reference:"cpio-2.7-3.1mdv2007.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.0", reference:"cpio-2.9-2.1mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
