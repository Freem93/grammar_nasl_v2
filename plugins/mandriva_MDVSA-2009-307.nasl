#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2009:307. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(42943);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/11/19 11:21:00 $");

  script_cve_id("CVE-2009-3736");
  script_bugtraq_id(37128);
  script_xref(name:"MDVSA", value:"2009:307-1");

  script_name(english:"Mandriva Linux Security Advisory : libtool (MDVSA-2009:307-1)");
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
"A vulnerability was discovered and corrected in libtool :

All versions of libtool prior to 2.2.6b suffers from a local privilege
escalation vulnerability that could be exploited under certain
conditions to load arbitrary code (CVE-2009-3736).

This advisory fixes this issue. Additionally, all applications
embedding the libtool code were patched in order to avoid possible
future exploitations of this issue.

Update :

Packages for 2008.0 are provided for Corporate Desktop 2008.0
customers"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:arts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcc-cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcc-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcc-gnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcc-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcc-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcc-objc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:gcj-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:heartbeat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:heartbeat-ldirectord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:heartbeat-pils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:heartbeat-stonith");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:imagemagick-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:imagemagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64arts1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64arts1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gcj-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gcj-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64gcj8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64heartbeat-apphb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64heartbeat-pils1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64heartbeat-pils1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64heartbeat-stonith1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64heartbeat-stonith1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64heartbeat1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64heartbeat1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ltdl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64ltdl3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64magick10.7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64magick10.7.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64prelude-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64prelude-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64prelude2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64tunepimp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64tunepimp5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libarts1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libarts1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libffi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libffi4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgcc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgcj-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgcj-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgcj8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgcj8-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgcj8-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgfortran2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgnat1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgomp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libgomp1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libheartbeat-apphb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libheartbeat-pils1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libheartbeat-pils1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libheartbeat-stonith1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libheartbeat-stonith1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libheartbeat1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libheartbeat1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libltdl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libltdl3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmagick10.7.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmagick10.7.0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmudflap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libmudflap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libobjc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libprelude-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libprelude-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libprelude2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libstdc++-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libstdc++6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtool-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtunepimp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtunepimp5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-Image-Magick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-prelude");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:prelude-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_autohost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_ban");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_case");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_ctrls_admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_gss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_ifsession");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_load");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_quotatab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_quotatab_file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_quotatab_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_quotatab_radius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_quotatab_sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_radius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_ratio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_rewrite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_shaper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_site_misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_sql_mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_sql_postgres");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_time");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_tls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_wrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_wrap_file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:proftpd-mod_wrap_sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-prelude");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-tunepimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:smalltalk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tunepimp-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:tunepimp-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2008.0", reference:"arts-1.5.7-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gcc-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gcc-c++-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gcc-cpp-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gcc-doc-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gcc-doc-pdf-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gcc-gfortran-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gcc-gnat-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gcc-java-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gcc-objc-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gcc-objc++-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"gcj-tools-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"heartbeat-2.0.8-4.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"heartbeat-ldirectord-2.0.8-4.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"heartbeat-pils-2.0.8-4.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"heartbeat-stonith-2.0.8-4.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"imagemagick-6.3.2.9-10.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"imagemagick-desktop-6.3.2.9-10.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"imagemagick-doc-6.3.2.9-10.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64arts1-1.5.7-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64arts1-devel-1.5.7-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64gcj-devel-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64gcj-static-devel-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64gcj8-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64heartbeat-apphb0-2.0.8-4.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64heartbeat-pils1-2.0.8-4.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64heartbeat-pils1-devel-2.0.8-4.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64heartbeat-stonith1-2.0.8-4.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64heartbeat-stonith1-devel-2.0.8-4.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64heartbeat1-2.0.8-4.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64heartbeat1-devel-2.0.8-4.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64ltdl3-1.5.22-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64ltdl3-devel-1.5.22-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64magick10.7.0-6.3.2.9-10.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64magick10.7.0-devel-6.3.2.9-10.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64prelude-devel-0.9.15.2-1.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64prelude-static-devel-0.9.15.2-1.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64prelude2-0.9.15.2-1.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64tunepimp-devel-0.5.3-5.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"x86_64", reference:"lib64tunepimp5-0.5.3-5.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libarts1-1.5.7-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libarts1-devel-1.5.7-2.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"libffi-devel-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"libffi4-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"libgcc1-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libgcj-devel-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libgcj-static-devel-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libgcj8-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"libgcj8-base-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"libgcj8-src-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"libgfortran2-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"libgnat1-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"libgomp-devel-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"libgomp1-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libheartbeat-apphb0-2.0.8-4.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libheartbeat-pils1-2.0.8-4.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libheartbeat-pils1-devel-2.0.8-4.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libheartbeat-stonith1-2.0.8-4.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libheartbeat-stonith1-devel-2.0.8-4.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libheartbeat1-2.0.8-4.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libheartbeat1-devel-2.0.8-4.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libltdl3-1.5.22-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libltdl3-devel-1.5.22-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libmagick10.7.0-6.3.2.9-10.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libmagick10.7.0-devel-6.3.2.9-10.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"libmudflap-devel-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"libmudflap0-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"libobjc2-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libprelude-devel-0.9.15.2-1.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libprelude-static-devel-0.9.15.2-1.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libprelude2-0.9.15.2-1.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"libstdc++-devel-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"libstdc++-static-devel-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"libstdc++6-4.2.2-3.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"libtool-1.5.22-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"libtool-base-1.5.22-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libtunepimp-devel-0.5.3-5.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", cpu:"i386", reference:"libtunepimp5-0.5.3-5.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"perl-Image-Magick-6.3.2.9-10.5mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"perl-prelude-0.9.15.2-1.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"prelude-tools-0.9.15.2-1.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-devel-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_autohost-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_ban-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_case-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_ctrls_admin-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_gss-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_ifsession-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_ldap-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_load-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_quotatab-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_quotatab_file-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_quotatab_ldap-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_quotatab_radius-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_quotatab_sql-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_radius-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_ratio-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_rewrite-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_shaper-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_site_misc-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_sql-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_sql_mysql-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_sql_postgres-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_time-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_tls-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_wrap-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_wrap_file-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"proftpd-mod_wrap_sql-1.3.2-0.2mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"python-prelude-0.9.15.2-1.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"python-tunepimp-0.5.3-5.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"smalltalk-2.3.3-3.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tunepimp-plugins-0.5.3-5.1mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"tunepimp-utils-0.5.3-5.1mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
