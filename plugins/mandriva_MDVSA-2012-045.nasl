#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:045. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(58557);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/10/16 10:40:37 $");

  script_cve_id("CVE-2011-4128");
  script_bugtraq_id(50609);
  script_xref(name:"MDVSA", value:"2012:045");

  script_name(english:"Mandriva Linux Security Advisory : gnutls (MDVSA-2012:045)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability has been found and corrected in GnuTLS :

Buffer overflow in the gnutls_session_get_data function in
lib/gnutls_session.c in GnuTLS 2.12.x before 2.12.14 and 3.x before
3.0.7, when used on a client that performs nonstandard session
resumption, allows remote TLS servers to cause a denial of service
(application crash) via a large SessionTicket (CVE-2011-4128).

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gnutls-ssl27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gnutls26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgnutls-ssl27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgnutls26");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2010.1", reference:"gnutls-2.8.6-1.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64gnutls-devel-2.8.6-1.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64gnutls26-2.8.6-1.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libgnutls-devel-2.8.6-1.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libgnutls26-2.8.6-1.2mdv2010.2", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2011", reference:"gnutls-2.12.8-0.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64gnutls-devel-2.12.8-0.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64gnutls-ssl27-2.12.8-0.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64gnutls26-2.12.8-0.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libgnutls-devel-2.12.8-0.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libgnutls-ssl27-2.12.8-0.2-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libgnutls26-2.12.8-0.2-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
