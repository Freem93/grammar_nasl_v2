#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2002:039. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(14778);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/31 23:43:26 $");

  script_cve_id("CVE-2002-0392");
  script_xref(name:"MDKSA", value:"2002:039-2");

  script_name(english:"Mandrake Linux Security Advisory : apache (MDKSA-2002:039-2)");
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
"[ Please note that this advisory supersedes the previous
MDKSA-2002:039 and MDKSA-2002:039-1 advisories. ]

MandrakeSoft is urging all users of Mandrake Linux to update their
Apache installations immediately. What was previously thought to have
been a DoS-only condition has now been proven to be more than that;
exploitable conditions have been discovered on both 32bit and 64bit
platforms. Successful exploitation of this vulnerability may lead to
the execution of arbitary code on the server running a vulnerable
Apache with the permissions of the web server child process (on
Mandrake Linux this is the user 'apache'). This can be used to exploit
other vulnerabilities that are unrelated to Apache on the local
system, and potentially allow the intruder root access.

Thanks to Gobbles for proving that this exploitable condition exists.
Because there are known exploits in the wild for some platforms, this
update should be considered essential and should be performed
immediately.

All versions of Apache prior to 1.3.26 and 2.0.37 are vulnerable to
this problem. MandrakeSoft has provided patched versions of Apache to
correct this vulnerability.

Also please note that these packages are no different than those
provided in MDKSA-2002:039-1 so if you have already updated, there are
no new packages to upgrade."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://httpd.apache.org/info/security_bulletin_20020617.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://httpd.apache.org/info/security_bulletin_20020620.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://online.securityfocus.com/news/493"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Win32 Chunked Encoding');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:HTML-Embperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mod_perl-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mod_perl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/06/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"HTML-Embperl-1.3.22_1.3.4-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"apache-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"apache-common-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"apache-devel-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"apache-manual-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"apache-mod_perl-1.3.22_1.26-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"apache-modules-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"apache-source-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"mod_perl-common-1.3.22_1.26-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"mod_perl-devel-1.3.22_1.26-2.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"HTML-Embperl-1.3.22_1.3.4-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"apache-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"apache-common-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"apache-devel-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"apache-manual-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"apache-mod_perl-1.3.22_1.26-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"apache-modules-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"apache-source-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"mod_perl-common-1.3.22_1.26-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"mod_perl-devel-1.3.22_1.26-2.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"HTML-Embperl-1.3.22_1.3.4-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"apache-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"apache-common-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"apache-devel-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"apache-manual-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"apache-mod_perl-1.3.22_1.26-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"apache-modules-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"apache-source-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"mod_perl-common-1.3.22_1.26-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"mod_perl-devel-1.3.22_1.26-2.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"HTML-Embperl-1.3.22_1.3.4-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"apache-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"apache-common-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"apache-devel-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"apache-manual-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"apache-mod_perl-1.3.22_1.26-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"apache-modules-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"apache-source-1.3.22-10.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"mod_perl-common-1.3.22_1.26-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"mod_perl-devel-1.3.22_1.26-4.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"HTML-Embperl-1.3.23_1.3.4-5.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"apache-1.3.23-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"apache-common-1.3.23-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"apache-devel-1.3.23-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"apache-manual-1.3.23-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"apache-mod_perl-1.3.23_1.26-5.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"apache-modules-1.3.23-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"apache-source-1.3.23-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"mod_perl-common-1.3.23_1.26-5.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"mod_perl-devel-1.3.23_1.26-5.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
