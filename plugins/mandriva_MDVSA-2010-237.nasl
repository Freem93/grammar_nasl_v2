#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2010:237. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(50609);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/05/02 10:37:32 $");

  script_cve_id("CVE-2010-2761", "CVE-2010-4410");
  script_xref(name:"MDVSA", value:"2010:237");

  script_name(english:"Mandriva Linux Security Advisory : perl-CGI (MDVSA-2010:237)");
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
"A new version of the CGI Perl module has been released to CPAN, which
fixes several security bugs which directly affect Bugzilla (these two
security bugs where first discovered as affecting Bugzilla, then
identified as being bugs in CGI.pm itself).

The multipart_init function in (1) CGI.pm before 3.50 and (2)
Simple.pm in CGI::Simple 1.112 and earlier uses a hard-coded value of
the MIME boundary string in multipart/x-mixed-replace content, which
allows remote attackers to inject arbitrary HTTP headers and conduct
HTTP response splitting attacks via crafted input that contains this
value, a different vulnerability than CVE-2010-3172 (CVE-2010-2761).

CRLF injection vulnerability in the header function in (1) CGI.pm
before 3.50 and (2) Simple.pm in CGI::Simple 1.112 and earlier allows
remote attackers to inject arbitrary HTTP headers and conduct HTTP
response splitting attacks via vectors related to non-whitespace
characters preceded by newline characters, a different vulnerability
than CVE-2010-2761 and CVE-2010-3172 (CVE-2010-4410).

Packages for 2009.0 are provided as of the Extended Maintenance
Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149&amp;products_id=4
90

The updated packages have been upgraded to perl-CGI 3.50 to solve
these security issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.bugzilla.org/security/3.2.8/"
  );
  # http://www.nntp.perl.org/group/perl.perl5.changes/2010/11/msg28043.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41507149"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected perl-CGI and / or perl-CGI-Fast packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-CGI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perl-CGI-Fast");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.0", reference:"perl-CGI-3.50-0.1mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"perl-CGI-Fast-3.50-0.1mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.0", reference:"perl-CGI-3.500.0-0.1mdv2010.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.0", reference:"perl-CGI-Fast-3.500.0-0.1mdv2010.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", reference:"perl-CGI-3.500.0-0.1mdv2010.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"perl-CGI-Fast-3.500.0-0.1mdv2010.1", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
