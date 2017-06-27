#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:169. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82422);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/11/28 21:52:55 $");

  script_cve_id("CVE-2014-9390");
  script_xref(name:"MDVSA", value:"2015:169");

  script_name(english:"Mandriva Linux Security Advisory : git (MDVSA-2015:169)");
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
"Updated git packages fix security vulnerability :

It was reported that git, when used as a client on a case-insensitive
filesystem, could allow the overwrite of the .git/config file when the
client performed a git pull. Because git permitted committing
.Git/config (or any case variation), on the pull this would replace
the user's .git/config. If this malicious config file contained
defined external commands (such as for invoking and editor or an
external diff utility) it could allow for the execution of arbitrary
code with the privileges of the user running the git client
(CVE-2014-9390)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0546.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Malicious Git and Mercurial HTTP Server For CVE-2014-9390');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:git-arch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:git-core-oldies");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:git-prompt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gitk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gitview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gitweb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64git-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-Git");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"git-1.8.5.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"git-arch-1.8.5.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"git-core-1.8.5.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"git-core-oldies-1.8.5.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"git-cvs-1.8.5.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"git-email-1.8.5.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"git-prompt-1.8.5.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"git-svn-1.8.5.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"gitk-1.8.5.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"gitview-1.8.5.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"gitweb-1.8.5.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64git-devel-1.8.5.6-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"perl-Git-1.8.5.6-1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
