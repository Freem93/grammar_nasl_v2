#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:092. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(37998);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/11/14 12:03:06 $");

  script_cve_id("CVE-2009-0159");
  script_bugtraq_id(34481);
  script_xref(name:"MDVSA", value:"2009:092");

  script_name(english:"Mandriva Linux Security Advisory : ntp (MDVSA-2009:092)");
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
"A vulnerability has been found and corrected in ntp :

Requesting peer information from a malicious remote time server may
lead to an unexpected application termination or arbitrary code
execution (CVE-2009-0159).

The updated packages have been patched to correct this issue."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ntp, ntp-client and / or ntp-doc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ntp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.1", reference:"ntp-4.2.4-15.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"ntp-client-4.2.4-15.2mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"ntp-doc-4.2.4-15.2mdv2008.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", reference:"ntp-4.2.4-18.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"ntp-client-4.2.4-18.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"ntp-doc-4.2.4-18.2mdv2009.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
