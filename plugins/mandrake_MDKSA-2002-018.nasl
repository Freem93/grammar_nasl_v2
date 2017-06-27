#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2002:018. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(13926);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/17 17:02:53 $");

  script_cve_id("CVE-2001-0869");
  script_bugtraq_id(3498);
  script_xref(name:"MDKSA", value:"2002:018");

  script_name(english:"Mandrake Linux Security Advisory : cyrus-sasl (MDKSA-2002:018)");
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
"Kari Hurtta discovered that a format bug exists in the Cyrus SASL
library, which is used to provide an authentication API for mail
clients and servers, as well as other services such as LDAP. The
format bug was found in one of the logging functions which could be
used by an attacker to obtain access to a machine or to possibly
acquire elevated privileges. Thanks to the SuSE security team for
providing the fix."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cyrus-sasl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl7-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl7-plug-anonymous");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl7-plug-crammd5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl7-plug-digestmd5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl7-plug-login");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsasl7-plug-plain");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"cyrus-sasl-1.5.27-2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"libsasl7-1.5.27-2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"libsasl7-devel-1.5.27-2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"libsasl7-plug-anonymous-1.5.27-2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"libsasl7-plug-crammd5-1.5.27-2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"libsasl7-plug-digestmd5-1.5.27-2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"libsasl7-plug-login-1.5.27-2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"libsasl7-plug-plain-1.5.27-2.2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"cyrus-sasl-1.5.27-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"libsasl7-1.5.27-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"libsasl7-devel-1.5.27-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"libsasl7-plug-anonymous-1.5.27-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"libsasl7-plug-crammd5-1.5.27-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"libsasl7-plug-digestmd5-1.5.27-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"libsasl7-plug-login-1.5.27-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"libsasl7-plug-plain-1.5.27-2.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
