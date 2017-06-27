#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:136. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(66148);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/05/06 11:35:45 $");

  script_cve_id("CVE-2012-5534", "CVE-2012-5854");
  script_bugtraq_id(56482, 56584);
  script_xref(name:"MDVSA", value:"2013:136");
  script_xref(name:"MGASA", value:"2012-0330");
  script_xref(name:"MGASA", value:"2012-0347");

  script_name(english:"Mandriva Linux Security Advisory : weechat (MDVSA-2013:136)");
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
"Updated weechat packages fix security vulnerability :

A buffer overflow is causing a crash or freeze of WeeChat (0.36 to
0.39) when decoding IRC colors in strings. The packages have been
patched to fix this problem (CVE-2012-5854).

Untrusted command for function hook_process in WeeChat before 0.3.9.2
could lead to execution of commands, because of shell expansions (so
the problem is only caused by some scripts, not by WeeChat itself)
(CVE-2012-5534)."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:weechat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:weechat-aspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:weechat-charset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:weechat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:weechat-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:weechat-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:weechat-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:weechat-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:weechat-tcl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"weechat-0.3.6-4.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"weechat-aspell-0.3.6-4.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"weechat-charset-0.3.6-4.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"weechat-devel-0.3.6-4.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"weechat-lua-0.3.6-4.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"weechat-perl-0.3.6-4.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"weechat-python-0.3.6-4.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"weechat-ruby-0.3.6-4.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"weechat-tcl-0.3.6-4.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
