#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2001:077. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(13892);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/28 21:39:21 $");

  script_cve_id("CVE-2001-0730", "CVE-2001-0731", "CVE-2001-0925", "CVE-2001-1449");
  script_bugtraq_id(2503, 3009);
  script_xref(name:"MDKSA", value:"2001:077-1");

  script_name(english:"Mandrake Linux Security Advisory : apache (MDKSA-2001:077-1)");
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
"A problem exists with all Apache servers prior to version 1.3.19. The
vulnerablity could allow directory indexing and path discovery on the
vulnerable servers with a custom crafted request consisting of a long
path name created artificially by using numerous slashes. This can
cause modules to misbehave and return a listing of the directory
contents by avoiding the error page.

Another vulnerability found by Procheckup (www.procheckup.com) was
that all directories, by default, were configured as browseable so an
attacker could list all files in the targeted directories. As well,
Procheckup found that the perl-proxy/management software on port 8200
would supply dangerous information to attackers due to a perl status
script that was enabled. We have disabled directory browsing by
default and have disabled the perl status scripts.

Update :

The previous updates for 7.2 had some problems with mod_perl
segfaulting and with mod_ssl under 7.1. As well, ApacheJServ was not
included for 7.2 and 8.0.

Other security fixes were introduced in Apache 1.3.22. A vulnerability
in the split-logfile support program would allow any file with a .log
extension on the system to be written to due to a specially crafted
Host: header.

This update provides Apache 1.3.22 for all supported platforms, and
the packages for 7.1, 7.2, and Corporate Server 1.0.1 now use the same
modular design as 8.0 and later versions. You will be unable to safely
upgrade these packages and will need to take a few very important
manual steps to ensure a proper upgrade (this is only applicable to
7.2 and earlier distributions; this is not required for 8.0 and 
later) :

1) Stop apache (service httpd stop) 2) Completely backup
/etc/httpd/conf/* 3) Backup /var/log/httpd (the uninstall scripts of
the previous apache versions may remove the log files) 4) Remove the
currently installed apache, mod_perl, mod_ssl, and php packages from
the system. You can do this using :

urpme apache; urpme php

or (if you are using 7.2) :

urpme apache-common; urpme php

5) Upgrade mm/mm-devel and (if you are upgrading 7.1 or Corporate
Server) the new perl packages 6) Install the download upgrade packages
of apache components using 'rpm -ivh *.rpm' 7) Restore your
/var/log/httpd backup 8) Merge your configuration backups with the new
config files (most notably you will need to edit commonhttpd.conf) 9)
Start apache (service httpd start)

This update also introduces PHP 4.0.6 to Linux-Mandrake 7.1, 7.2, and
Corporate Server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.apache.org/index.cgi/full/7848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.apacheweek.com/issues/01-09-28#security"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.procheckup.com/vulnerabilities/pr0107.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:ApacheJServ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:HTML-Embperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-conf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-mod_perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mod_auth_external");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mod_auth_radius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mod_frontpage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mod_gzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mod_perl-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mod_perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mod_php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mod_sxnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-dba_gdbm_db2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-manual_en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:php-readline");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:7.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2001/11/27");
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
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"HTML-Embperl-1.3.22_1.3.3-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"apache-1.3.22-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"apache-common-1.3.22-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"apache-conf-1.3.22-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"apache-devel-1.3.22-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"apache-manual-1.3.22-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"apache-mod_perl-1.3.22_1.25_01-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"apache-modules-1.3.22-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"apache-source-1.3.22-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"apache-suexec-1.3.22-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"mm-1.1.3-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"mm-devel-1.1.3-8.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"mod_perl-common-1.3.22_1.25_01-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"mod_perl-devel-1.3.22_1.25_01-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"mod_php-4.0.6-5.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"mod_ssl-2.8.5-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"mod_sxnet-1.2.4-1.4mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"perl-5.600-17mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"perl-base-5.600-17mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"perl-devel-5.600-17mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"php-4.0.6-5.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"php-common-4.0.6-5.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"php-dba_gdbm_db2-4.0.6-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"php-devel-4.0.6-5.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"php-gd-4.0.6-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"php-imap-4.0.6-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"php-ldap-4.0.6-3.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"php-manual_en-4.0.6-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"php-mysql-4.0.6-3.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"php-pgsql-4.0.6-3.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.1", cpu:"i386", reference:"php-readline-4.0.6-2.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"ApacheJServ-1.1.2-6.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"HTML-Embperl-1.3.22_1.3.3-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"apache-1.3.22-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"apache-common-1.3.22-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"apache-conf-1.3.22-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"apache-devel-1.3.22-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"apache-manual-1.3.22-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"apache-mod_perl-1.3.22_1.25_01-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"apache-modules-1.3.22-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"apache-source-1.3.22-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"apache-suexec-1.3.22-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"mm-1.1.3-8.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"mm-devel-1.1.3-8.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"mod_perl-common-1.3.22_1.25_01-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"mod_perl-devel-1.3.22_1.25_01-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"mod_php-4.0.6-5.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"mod_ssl-2.8.5-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"mod_sxnet-1.2.4-1.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"php-4.0.6-5.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"php-common-4.0.6-5.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"php-dba_gdbm_db2-4.0.6-4.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"php-devel-4.0.6-5.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"php-gd-4.0.6-2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"php-imap-4.0.6-2.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"php-ldap-4.0.6-3.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"php-manual_en-4.0.6-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"php-mysql-4.0.6-3.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"php-pgsql-4.0.6-3.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK7.2", cpu:"i386", reference:"php-readline-4.0.6-2.2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"ApacheJServ-1.1.2-6.3mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"HTML-Embperl-1.3.22_1.3.3-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"apache-1.3.22-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"apache-common-1.3.22-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"apache-conf-1.3.22-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"apache-devel-1.3.22-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"apache-manual-1.3.22-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"apache-mod_perl-1.3.22_1.25_01-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"apache-modules-1.3.22-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"apache-source-1.3.22-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"apache-suexec-1.3.22-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"mod_frontpage-1.5.1-5.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"mod_perl-common-1.3.22_1.25_01-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"mod_perl-devel-1.3.22_1.25_01-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"mod_php-4.0.6-3.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"mod_ssl-2.8.5-1.2mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.0", cpu:"i386", reference:"mod_sxnet-1.2.4-1.2mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"HTML-Embperl-1.3.22_2.0b3-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"apache-1.3.22-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"apache-common-1.3.22-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"apache-conf-1.3.22-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"apache-devel-1.3.22-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"apache-manual-1.3.22-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"apache-mod_perl-1.3.22_1.26-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"apache-modules-1.3.22-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"apache-source-1.3.22-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"apache-suexec-1.3.22-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"mod_auth_external-2.1.12-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"mod_auth_radius-1.5.2-3.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"mod_frontpage-1.5.1-5.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"mod_gzip-1.3.19.1a-4.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"mod_perl-common-1.3.22_1.26-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"mod_perl-devel-1.3.22_1.26-2.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"mod_php-4.0.6-7.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"mod_ssl-2.8.5-1.1mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK8.1", cpu:"i386", reference:"mod_sxnet-1.2.4-7.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
