#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:183. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(57079);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/06/01 00:27:15 $");

  script_cve_id("CVE-2011-3594", "CVE-2011-4601");
  script_bugtraq_id(49912, 51010);
  script_xref(name:"MDVSA", value:"2011:183");

  script_name(english:"Mandriva Linux Security Advisory : pidgin (MDVSA-2011:183)");
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
"Multiple vulnerabilities has been discovered and corrected in pidgin :

When receiving various stanzas related to voice and video chat, the
XMPP protocol plugin failed to ensure that the incoming message
contained all required fields, and would crash if certain fields were
missing.

When receiving various messages related to requesting or receiving
authorization for adding a buddy to a buddy list, the oscar protocol
plugin failed to validate that a piece of text was UTF-8. In some
cases invalid UTF-8 data would lead to a crash (CVE-2011-4601).

When receiving various incoming messages, the SILC protocol plugin
failed to validate that a piece of text was UTF-8. In some cases
invalid UTF-8 data would lead to a crash (CVE-2011-3594).

This update provides pidgin 2.10.1, which is not vulnerable to these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://pidgin.im/news/security/?id=56"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://pidgin.im/news/security/?id=57"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://pidgin.im/news/security/?id=58"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.pidgin.im/news/security/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64finch0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64purple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64purple0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libfinch0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libpurple0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-bonjour");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-gevolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-meanwhile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-silc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-tcl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2010.1", reference:"finch-2.10.1-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64finch0-2.10.1-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64purple-devel-2.10.1-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64purple0-2.10.1-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libfinch0-2.10.1-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libpurple-devel-2.10.1-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libpurple0-2.10.1-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"pidgin-2.10.1-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"pidgin-bonjour-2.10.1-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"pidgin-client-2.10.1-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"pidgin-gevolution-2.10.1-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"pidgin-i18n-2.10.1-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"pidgin-meanwhile-2.10.1-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"pidgin-perl-2.10.1-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"pidgin-plugins-2.10.1-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"pidgin-silc-2.10.1-0.1mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"pidgin-tcl-2.10.1-0.1mdv2010.2", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2011", reference:"finch-2.10.1-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64finch0-2.10.1-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64purple-devel-2.10.1-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64purple0-2.10.1-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libfinch0-2.10.1-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libpurple-devel-2.10.1-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libpurple0-2.10.1-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"pidgin-2.10.1-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"pidgin-bonjour-2.10.1-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"pidgin-client-2.10.1-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"pidgin-gevolution-2.10.1-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"pidgin-i18n-2.10.1-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"pidgin-meanwhile-2.10.1-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"pidgin-perl-2.10.1-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"pidgin-plugins-2.10.1-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"pidgin-silc-2.10.1-0.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"pidgin-tcl-2.10.1-0.1-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
