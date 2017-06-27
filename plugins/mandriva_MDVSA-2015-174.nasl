#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:174. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82484);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/04/01 13:32:21 $");

  script_cve_id("CVE-2014-1693");
  script_xref(name:"MDVSA", value:"2015:174");

  script_name(english:"Mandriva Linux Security Advisory : erlang (MDVSA-2015:174)");
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
"Updated erlang packages fixes security vulnerability :

An FTP command injection flaw was found in Erlang's FTP module.
Several functions in the FTP module do not properly sanitize the input
before passing it into a control socket. A local attacker can use this
flaw to execute arbitrary FTP commands on a system that uses this
module (CVE-2014-1693).

This update also disables SSLv3 by default to mitigate the POODLE
issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0553.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-appmon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-asn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-common_test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-compiler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-cosEvent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-cosEventDomain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-cosFileTransfer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-cosNotification");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-cosProperty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-cosTime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-cosTransactions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-dialyzer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-diameter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-docbuilder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-edoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-eldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-erl_docgen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-erl_interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-eunit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-gs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-hipe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-ic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-inets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-jinterface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-manpages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-megaco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-mnesia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-observer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-orber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-os_mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-otp_mibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-parsetools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-percept");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-pman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-public_key");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-reltool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-runtime_tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-stack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-syntax_tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-test_server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-toolbar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-tv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-typer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-webtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-wx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:erlang-xmerl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-appmon-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-asn1-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-base-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-common_test-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-compiler-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-cosEvent-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-cosEventDomain-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-cosFileTransfer-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-cosNotification-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-cosProperty-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-cosTime-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-cosTransactions-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-crypto-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-debugger-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-devel-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-dialyzer-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-diameter-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-docbuilder-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-edoc-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-eldap-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-emacs-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-erl_docgen-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-erl_interface-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-et-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-eunit-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-gs-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-hipe-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-ic-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-inets-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-jinterface-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-manpages-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-megaco-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-mnesia-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-observer-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-odbc-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-orber-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-os_mon-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-otp_mibs-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-parsetools-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-percept-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-pman-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-public_key-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-reltool-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-runtime_tools-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-snmp-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-ssh-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-ssl-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-stack-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-syntax_tools-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-test_server-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-toolbar-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-tools-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-tv-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-typer-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-webtool-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-wx-R16B02-3.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"erlang-xmerl-R16B02-3.1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
