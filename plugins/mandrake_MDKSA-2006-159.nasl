#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2006:159. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(23903);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/31 23:56:39 $");

  script_cve_id("CVE-2005-4158", "CVE-2006-0151");
  script_xref(name:"DSA", value:"946");
  script_xref(name:"MDKSA", value:"2006:159");

  script_name(english:"Mandrake Linux Security Advisory : sudo (MDKSA-2006:159)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandrake Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Previous sudo updates were made available to sanitize certain
environment variables from affecting a sudo call, such as
PYTHONINSPECT, PERL5OPT, etc. While those updates were effective in
addressing those specific environment variables, other variables that
were not blacklisted were being made available.

Debian addressed this issue by forcing sudo to use a whitlist approach
in DSA-946-2 by arbitrarily making env_reset the default (as opposed
to having to be enabled in /etc/sudoers). Mandriva has opted to follow
the same approach so now only certain variables are, by default, made
available, such as HOME, LOGNAME, SHELL, TERM, DISPLAY, XAUTHORITY,
XAUTHORIZATION, LANG, LANGUAGE, LC_*, and USER, as well as the SUDO_*
variables.

If other variables are required to be kept, this can be done by
editing /etc/sudoers and using the env_keep option, such as :

Defaults env_keep='FOO BAR'

As well, the Corporate 3 packages are now compiled with the
SECURE_PATH setting.

Updated packages are patched to address this issue."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sudo package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:sudo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2006");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2006.0", reference:"sudo-1.6.8p8-2.3.20060mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
