
#
# (C) Tenable Network Security, Inc.
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(56709);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2011-1424: perl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2011-1424");
 script_set_attribute(attribute: "description", value: '
Updated perl packages that fix two security issues are now available for
Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having moderate
security impact. Common Vulnerability Scoring System (CVSS) base scores,
which give detailed severity ratings, are available for each vulnerability
from the CVE links in the References section.

Perl is a high-level programming language commonly used for system
administration utilities and web programming.

A heap-based buffer overflow flaw was found in the way Perl decoded Unicode
strings. An attacker could create a malicious Unicode string that, when
decoded by a Perl program, would cause the program to crash or,
potentially, execute arbitrary code with the permissions of the user
running the program. (CVE-2011-2939)

It was found that the "new" constructor of the Digest module used its
argument as part of the string expression passed to the eval() function. An
attacker could possibly use this flaw to execute arbitrary Perl code with
the privileges of a Perl program that uses untrusted input as an argument
to the constructor. (CVE-2011-3597)

All Perl users should upgrade to these updated packages, which contain
backported patches to correct these issues. All running Perl programs must
be restarted for this update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2011-1424.html");
script_set_attribute(attribute: "solution", value: "Update the affected package(s) using, for example, 'yum update'.");
script_set_attribute(attribute: "plugin_type", value: "local");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/04");
  script_cvs_date("$Date: 2012/07/24 16:19:35 $");
script_end_attributes();

script_cve_id("CVE-2011-2939", "CVE-2011-3597");
script_summary(english: "Check for the version of the perl packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

flag = 0;

if ( rpm_check( reference:"perl-5.10.1-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Archive-Extract-0.38-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Archive-Tar-1.58-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-CGI-3.51-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-CPAN-1.9402-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-CPANPLUS-0.88-119.el6_1.1", release:'RHEL6') ) flag ++;
# nb: see RHBA-2012-0843
# if ( rpm_check( reference:"perl-Compress-Raw-Zlib-2.023-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Compress-Zlib-2.020-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Digest-SHA-5.47-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-ExtUtils-CBuilder-0.27-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-ExtUtils-Embed-1.28-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-ExtUtils-MakeMaker-6.55-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-ExtUtils-ParseXS-2.2003.0-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-File-Fetch-0.26-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-IO-Compress-Base-2.020-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-IO-Compress-Zlib-2.020-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-IO-Zlib-1.09-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-IPC-Cmd-0.56-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Locale-Maketext-Simple-0.18-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Log-Message-0.02-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Log-Message-Simple-0.04-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Module-Build-0.3500-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Module-CoreList-2.18-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Module-Load-0.16-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Module-Load-Conditional-0.30-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Module-Loaded-0.02-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Module-Pluggable-3.90-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Object-Accessor-0.34-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Package-Constants-0.02-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Params-Check-0.26-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Parse-CPAN-Meta-1.40-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Pod-Escapes-1.04-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Pod-Simple-3.13-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Term-UI-0.20-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Test-Harness-3.17-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Test-Simple-0.92-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Time-HiRes-1.9721-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Time-Piece-1.15-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-core-5.10.1-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-debuginfo-5.10.1-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-devel-5.10.1-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-libs-5.10.1-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-parent-0.221-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-suidperl-5.10.1-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-version-0.77-119.el6_1.1", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-5.10.1-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Archive-Extract-0.38-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Archive-Tar-1.58-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-CGI-3.51-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-CPAN-1.9402-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-CPANPLUS-0.88-119.el6_1.1", release:'RHEL6.1') ) flag ++;
# nb: see RHBA-2012-0843
# if ( rpm_check( reference:"perl-Compress-Raw-Zlib-2.023-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Compress-Zlib-2.020-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Digest-SHA-5.47-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-ExtUtils-CBuilder-0.27-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-ExtUtils-Embed-1.28-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-ExtUtils-MakeMaker-6.55-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-ExtUtils-ParseXS-2.2003.0-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-File-Fetch-0.26-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-IO-Compress-Base-2.020-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-IO-Compress-Zlib-2.020-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-IO-Zlib-1.09-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-IPC-Cmd-0.56-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Locale-Maketext-Simple-0.18-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Log-Message-0.02-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Log-Message-Simple-0.04-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Module-Build-0.3500-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Module-CoreList-2.18-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Module-Load-0.16-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Module-Load-Conditional-0.30-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Module-Loaded-0.02-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Module-Pluggable-3.90-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Object-Accessor-0.34-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Package-Constants-0.02-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Params-Check-0.26-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Parse-CPAN-Meta-1.40-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Pod-Escapes-1.04-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Pod-Simple-3.13-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Term-UI-0.20-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Test-Harness-3.17-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Test-Simple-0.92-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Time-HiRes-1.9721-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-Time-Piece-1.15-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-core-5.10.1-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-debuginfo-5.10.1-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-devel-5.10.1-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-libs-5.10.1-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-parent-0.221-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-suidperl-5.10.1-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if ( rpm_check( reference:"perl-version-0.77-119.el6_1.1", release:'RHEL6.1') ) flag ++;
if (flag)
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
