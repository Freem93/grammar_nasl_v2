#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:343. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(43605);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/06/01 00:11:06 $");

  script_cve_id("CVE-2009-4235");
  script_xref(name:"MDVSA", value:"2009:343");

  script_name(english:"Mandriva Linux Security Advisory : acpid (MDVSA-2009:343)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandriva Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability has been found and corrected in acpid :

acpid 1.0.4 sets an unrestrictive umask, which might allow local users
to leverage weak permissions on /var/log/acpid, and obtain sensitive
information by reading this file or cause a denial of service by
overwriting this file, a different vulnerability than CVE-2009-4033
(CVE-2009-4235).

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers.

This update provides a solution to this vulnerability."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected acpid package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:acpid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/28");
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
if (rpm_check(release:"MDK2008.0", reference:"acpid-1.0.6-1.3mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", reference:"acpid-1.0.6-6.2mnb2")) flag++;

if (rpm_check(release:"MDK2009.1", reference:"acpid-1.0.8-1.2mnb2")) flag++;

if (rpm_check(release:"MDK2010.0", reference:"acpid-1.0.10-1.1mnb2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
