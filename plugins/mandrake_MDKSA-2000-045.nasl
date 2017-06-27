#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2000:045. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(61837);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/05/31 23:43:24 $");

  script_cve_id("CVE-2000-0824");
  script_xref(name:"MDKSA", value:"2000:045-1");

  script_name(english:"Mandrake Linux Security Advisory : glibc (MDKSA-2000:045-1)");
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
"A bug was discovered in ld.so that could allow local users to obtain
root privileges. The dynamic loader, ld.so, is responsible for making
shared libraries available within a program at run-time. Normally, a
user is allowed to load additional shared libraries when executing a
program; they can be specified with environment variables such as
LD_PRELOAD. Because this is not acceptable for applications that are
setuid root, ld.so normally removes these environment variables for
setuid root programs. The discovered bug causes these environment
variables to not be removed under certain circumstances. While setuid
programs themselves are not vulnerable, external programs they execute
can be affected by this problem.

A number of additional bugs have been found in the glibc locale and
internationaliztion security checks. In internationalized programs,
users are permitted to select a locale or choose message catalogues
using environment variables such as LANG or LC_*. The content of these
variables is then used as part of the pathname used to search message
catalogues or locale files. Under normal circumstances, if these
variables contained the '/' character, a program could load the
internationalization files from arbitrary directories. This is not
acceptable for setuid programs, which is the reason glibc does not
allow certain settings of these variables if the program is setuid or
setgid. However, some of these checks were done in inapporpriate
places, contained bugs, or were missing entirely. It is highly
probable that some of these bugs can be used for local root exploits.

Update :

Packages are now available for Linux-Mandrake 6.0 and 6.1."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected glibc, glibc-devel and / or glibc-profile
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:6.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2000/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
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
if (rpm_check(release:"MDK6.0", cpu:"i386", reference:"glibc-2.1.3-16mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.0", cpu:"i386", reference:"glibc-devel-2.1.3-16mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.0", cpu:"i386", reference:"glibc-profile-2.1.3-16mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"glibc-2.1.3-16mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"glibc-devel-2.1.3-16mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK6.1", cpu:"i386", reference:"glibc-profile-2.1.3-16mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
