#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2013-177.
#

include("compat.inc");

if (description)
{
  script_id(69736);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/22 14:14:32 $");

  script_cve_id("CVE-2012-5195", "CVE-2012-5526", "CVE-2012-6329", "CVE-2013-1667");
  script_xref(name:"ALAS", value:"2013-177");
  script_xref(name:"RHSA", value:"2013:0685");

  script_name(english:"Amazon Linux AMI : perl (ALAS-2013-177)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A heap overflow flaw was found in Perl. If a Perl application allowed
user input to control the count argument of the string repeat
operator, an attacker could cause the application to crash or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2012-5195)

A denial of service flaw was found in the way Perl's rehashing code
implementation, responsible for recalculation of hash keys and
redistribution of hash content, handled certain input. If an attacker
supplied specially crafted input to be used as hash keys by a Perl
application, it could cause excessive memory consumption.
(CVE-2013-1667)

It was found that the Perl CGI module, used to handle Common Gateway
Interface requests and responses, incorrectly sanitized the values for
Set-Cookie and P3P headers. If a Perl application using the CGI module
reused cookies values and accepted untrusted input from web browsers,
a remote attacker could use this flaw to alter member items of the
cookie or add new items. (CVE-2012-5526)

It was found that the Perl Locale::Maketext module, used to localize
Perl applications, did not properly handle backslashes or
fully-qualified method names. An attacker could possibly use this flaw
to execute arbitrary Perl code with the privileges of a Perl
application that uses untrusted Locale::Maketext templates.
(CVE-2012-6329)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2013-177.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update perl' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"TWiki 5.1.2 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'TWiki MAKETEXT Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Archive-Extract");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Archive-Tar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-CGI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-CPAN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-CPANPLUS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Compress-Raw-Bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Compress-Raw-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Compress-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Digest-SHA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ExtUtils-CBuilder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ExtUtils-Embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ExtUtils-MakeMaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ExtUtils-ParseXS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-File-Fetch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-IO-Compress-Base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-IO-Compress-Bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-IO-Compress-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-IO-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-IPC-Cmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Locale-Maketext-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Log-Message");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Log-Message-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Module-Build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Module-CoreList");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Module-Load");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Module-Load-Conditional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Module-Loaded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Module-Pluggable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Object-Accessor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Package-Constants");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Params-Check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Parse-CPAN-Meta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Pod-Escapes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Pod-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Term-UI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Test-Harness");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Test-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Time-HiRes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Time-Piece");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-suidperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-version");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/AmazonLinux/release")) audit(AUDIT_OS_NOT, "Amazon Linux AMI");
if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"perl-5.10.1-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Archive-Extract-0.38-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Archive-Tar-1.58-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-CGI-3.51-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-CPAN-1.9402-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-CPANPLUS-0.88-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Compress-Raw-Bzip2-2.020-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Compress-Raw-Zlib-2.023-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Compress-Zlib-2.020-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Digest-SHA-5.47-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-ExtUtils-CBuilder-0.27-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-ExtUtils-Embed-1.28-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-ExtUtils-MakeMaker-6.55-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-ExtUtils-ParseXS-2.2003.0-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-File-Fetch-0.26-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-IO-Compress-Base-2.020-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-IO-Compress-Bzip2-2.020-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-IO-Compress-Zlib-2.020-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-IO-Zlib-1.09-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-IPC-Cmd-0.56-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Locale-Maketext-Simple-0.18-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Log-Message-0.02-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Log-Message-Simple-0.04-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Module-Build-0.3500-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Module-CoreList-2.18-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Module-Load-0.16-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Module-Load-Conditional-0.30-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Module-Loaded-0.02-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Module-Pluggable-3.90-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Object-Accessor-0.34-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Package-Constants-0.02-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Params-Check-0.26-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Parse-CPAN-Meta-1.40-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Pod-Escapes-1.04-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Pod-Simple-3.13-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Term-UI-0.20-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Test-Harness-3.17-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Test-Simple-0.92-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Time-HiRes-1.9721-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Time-Piece-1.15-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-core-5.10.1-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-debuginfo-5.10.1-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-devel-5.10.1-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-libs-5.10.1-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-parent-0.221-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-suidperl-5.10.1-130.17.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-version-0.77-130.17.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl / perl-Archive-Extract / perl-Archive-Tar / perl-CGI / etc");
}
