#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:226. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(20457);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/03/19 14:42:14 $");

  script_cve_id("CVE-2005-3256");
  script_bugtraq_id(15155);
  script_xref(name:"MDKSA", value:"2005:226");

  script_name(english:"Mandrake Linux Security Advisory : mozilla-thunderbird (MDKSA-2005:226)");
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
"A bug in enigmail, the GPG support extension for Mozilla MailNews and
Mozilla Thunderbird was discovered that could lead to the encryption
of an email with the wrong public key. This could potentially disclose
confidential data to unintended recipients.

The updated packages have been patched to prevent this problem."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected mozilla-thunderbird, mozilla-thunderbird-enigmail
and / or mozilla-thunderbird-enigmime packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mozilla-thunderbird-enigmime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", reference:"mozilla-thunderbird-1.0.6-7.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-thunderbird-enigmail-1.0.6-7.2.20060mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK2006.0", reference:"mozilla-thunderbird-enigmime-1.0.6-7.2.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
