#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:147. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(39582);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/28 21:39:23 $");

  script_cve_id("CVE-2009-1373", "CVE-2009-1374", "CVE-2009-1375", "CVE-2009-1376");
  script_bugtraq_id(35067);
  script_xref(name:"MDVSA", value:"2009:147");

  script_name(english:"Mandriva Linux Security Advisory : pidgin (MDVSA-2009:147)");
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
"Security vulnerabilities has been identified and fixed in pidgin :

Buffer overflow in the XMPP SOCKS5 bytestream server in Pidgin
(formerly Gaim) before 2.5.6 allows remote authenticated users to
execute arbitrary code via vectors involving an outbound XMPP file
transfer. NOTE: some of these details are obtained from third-party
information (CVE-2009-1373).

Buffer overflow in the decrypt_out function in Pidgin (formerly Gaim)
before 2.5.6 allows remote attackers to cause a denial of service
(application crash) via a QQ packet (CVE-2009-1374).

The PurpleCircBuffer implementation in Pidgin (formerly Gaim) before
2.5.6 does not properly maintain a certain buffer, which allows remote
attackers to cause a denial of service (memory corruption and
application crash) via vectors involving the (1) XMPP or (2) Sametime
protocol (CVE-2009-1375).

Multiple integer overflows in the msn_slplink_process_msg functions in
the MSN protocol handler in (1) libpurple/protocols/msn/slplink.c and
(2) libpurple/protocols/msnp9/slplink.c in Pidgin (formerly Gaim)
before 2.5.6 on 32-bit platforms allow remote attackers to execute
arbitrary code via a malformed SLP message with a crafted offset
value, leading to buffer overflows. NOTE: this issue exists because of
an incomplete fix for CVE-2008-2927 (CVE-2009-1376).

This update provides pidgin 2.5.8, which is not vulnerable to these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://pidgin.im/news/security/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-silc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:pidgin-tcl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.0", reference:"finch-2.5.8-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64finch0-2.5.8-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64purple-devel-2.5.8-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64purple0-2.5.8-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libfinch0-2.5.8-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libpurple-devel-2.5.8-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libpurple0-2.5.8-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pidgin-2.5.8-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pidgin-bonjour-2.5.8-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pidgin-client-2.5.8-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pidgin-gevolution-2.5.8-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pidgin-i18n-2.5.8-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pidgin-meanwhile-2.5.8-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pidgin-mono-2.5.8-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pidgin-perl-2.5.8-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pidgin-plugins-2.5.8-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pidgin-silc-2.5.8-0.2mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"pidgin-tcl-2.5.8-0.2mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.1", reference:"finch-2.5.8-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64finch0-2.5.8-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64purple-devel-2.5.8-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"x86_64", reference:"lib64purple0-2.5.8-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libfinch0-2.5.8-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libpurple-devel-2.5.8-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", cpu:"i386", reference:"libpurple0-2.5.8-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pidgin-2.5.8-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pidgin-bonjour-2.5.8-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pidgin-client-2.5.8-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pidgin-gevolution-2.5.8-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pidgin-i18n-2.5.8-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pidgin-meanwhile-2.5.8-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pidgin-mono-2.5.8-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pidgin-perl-2.5.8-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pidgin-plugins-2.5.8-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pidgin-silc-2.5.8-0.2mdv2009.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.1", reference:"pidgin-tcl-2.5.8-0.2mdv2009.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
