#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2011-19.
#

include("compat.inc");

if (description)
{
  script_id(69578);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/30 14:43:52 $");

  script_cve_id("CVE-2011-2939", "CVE-2011-3597");
  script_xref(name:"ALAS", value:"2011-19");
  script_xref(name:"RHSA", value:"2011:1424");

  script_name(english:"Amazon Linux AMI : perl (ALAS-2011-19)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A heap-based buffer overflow flaw was found in the way Perl decoded
Unicode strings. An attacker could create a malicious Unicode string
that, when decoded by a Perl program, would cause the program to crash
or, potentially, execute arbitrary code with the permissions of the
user running the program. (CVE-2011-2939)

It was found that the 'new' constructor of the Digest module used its
argument as part of the string expression passed to the eval()
function. An attacker could possibly use this flaw to execute
arbitrary Perl code with the privileges of a Perl program that uses
untrusted input as an argument to the constructor. (CVE-2011-3597)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2011-19.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update perl' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Archive-Extract");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Archive-Tar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-CGI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-CPAN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-CPANPLUS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Compress-Raw-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Compress-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-Digest-SHA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ExtUtils-CBuilder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ExtUtils-Embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ExtUtils-MakeMaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-ExtUtils-ParseXS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-File-Fetch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perl-IO-Compress-Base");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/09");
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
if (rpm_check(release:"ALA", reference:"perl-5.10.1-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Archive-Extract-0.38-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Archive-Tar-1.58-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-CGI-3.51-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-CPAN-1.9402-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-CPANPLUS-0.88-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Compress-Raw-Zlib-2.023-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Compress-Zlib-2.020-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Digest-SHA-5.47-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-ExtUtils-CBuilder-0.27-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-ExtUtils-Embed-1.28-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-ExtUtils-MakeMaker-6.55-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-ExtUtils-ParseXS-2.2003.0-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-File-Fetch-0.26-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-IO-Compress-Base-2.020-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-IO-Compress-Zlib-2.020-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-IO-Zlib-1.09-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-IPC-Cmd-0.56-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Locale-Maketext-Simple-0.18-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Log-Message-0.02-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Log-Message-Simple-0.04-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Module-Build-0.3500-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Module-CoreList-2.18-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Module-Load-0.16-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Module-Load-Conditional-0.30-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Module-Loaded-0.02-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Module-Pluggable-3.90-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Object-Accessor-0.34-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Package-Constants-0.02-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Params-Check-0.26-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Parse-CPAN-Meta-1.40-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Pod-Escapes-1.04-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Pod-Simple-3.13-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Term-UI-0.20-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Test-Harness-3.17-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Test-Simple-0.92-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Time-HiRes-1.9721-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-Time-Piece-1.15-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-core-5.10.1-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-debuginfo-5.10.1-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-devel-5.10.1-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-libs-5.10.1-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-parent-0.221-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-suidperl-5.10.1-119.12.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perl-version-0.77-119.12.amzn1")) flag++;

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
