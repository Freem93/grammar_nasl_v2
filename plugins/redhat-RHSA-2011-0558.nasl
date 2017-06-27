
#
# (C) Tenable Network Security, Inc.
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(54593);
 script_version ("$Revision: 1.3 $");
 script_name(english: "RHSA-2011-0558: perl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2011-0558");
 script_set_attribute(attribute: "description", value: '
Updated perl packages that fix three security issues and several bugs are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having moderate
security impact. Common Vulnerability Scoring System (CVSS) base scores,
which give detailed severity ratings, are available for each vulnerability
from the CVE links in the References section.

Perl is a high-level programming language commonly used for system
administration utilities and web programming. The Perl CGI module provides
resources for preparing and processing Common Gateway Interface (CGI) based
HTTP requests and responses.

It was found that the Perl CGI module used a hard-coded value for the MIME
boundary string in multipart/x-mixed-replace content. A remote attacker
could possibly use this flaw to conduct an HTTP response splitting attack
via a specially crafted HTTP request. (CVE-2010-2761)

A CRLF injection flaw was found in the way the Perl CGI module processed a
sequence of non-whitespace preceded by newline characters in the header. A
remote attacker could use this flaw to conduct an HTTP response splitting
attack via a specially crafted sequence of characters provided to the CGI
module. (CVE-2010-4410)

It was found that certain Perl string manipulation functions (such as uc()
and lc()) failed to preserve the taint bit. A remote attacker could use
this flaw to bypass the Perl taint mode protection mechanism in scripts
that use the affected functions to process tainted input. (CVE-2011-1487)

These packages upgrade the CGI module to version 3.51. Refer to the CGI
module\'s Changes file, linked to in the References, for a full list of
changes.

This update also fixes the following bugs:

* When using the "threads" module, an attempt to send a signal to a thread
that did not have a signal handler specified caused the perl interpreter to
terminate unexpectedly with a segmentation fault. With this update, the
"threads" module has been updated to upstream version 1.82, which fixes
this bug. As a result, sending a signal to a thread that does not have the
signal handler specified no longer causes perl to crash. (BZ#626330)

* Prior to this update, the perl packages did not require the Digest::SHA
module as a dependency. Consequent to this, when a user started the cpan
command line interface and attempted to download a distribution from CPAN,
they may have been presented with the following message:

CPAN: checksum security checks disabled because Digest::SHA not installed.
Please consider installing the Digest::SHA module.

This update corrects the spec file for the perl package to require the
perl-Digest-SHA package as a dependency, and cpan no longer displays the
above message. (BZ#640716)

* When using the "threads" module, continual creation and destruction of
threads could cause the Perl program to consume an increasing amount of
memory. With this update, the underlying source code has been corrected to
free the allocated memory when a thread is destroyed, and the continual
creation and destruction of threads in Perl programs no longer leads to
memory leaks. (BZ#640720)

* Due to a packaging error, the perl packages did not include the
"NDBM_File" module. This update corrects this error, and "NDBM_File" is now
included as expected. (BZ#640729)

* Prior to this update, the prove(1) manual page and the "prove --help"
command listed "--fork" as a valid command line option. However, version
3.17 of the Test::Harness distribution removed the support for the
fork-based parallel testing, and the prove utility thus no longer supports
this option. This update corrects both the manual page and the output of
the "prove --help" command, so that "--fork" is no longer included in the
list of available command line options. (BZ#609492)

Users of Perl, especially those of Perl threads, are advised to upgrade to
these updated packages, which correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2011-0558.html");
script_set_attribute(attribute: "solution", value: "Update the affected package(s) using, for example, 'yum update'.");
script_set_attribute(attribute: "plugin_type", value: "local");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/20");
 script_cvs_date("$Date: 2014/08/18 18:39:01 $");
script_end_attributes();

 script_cve_id("CVE-2010-2761", "CVE-2010-4410", "CVE-2011-1487");
script_summary(english: "Check for the version of the perl packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

flag = 0;

if ( rpm_check( reference:"perl-5.10.1-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Archive-Extract-0.38-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Archive-Tar-1.58-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-CGI-3.51-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-CPAN-1.9402-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-CPANPLUS-0.88-119.el6", release:'RHEL6') ) flag ++;
# nb: see RHBA-2012-0843
# if ( rpm_check( reference:"perl-Compress-Raw-Zlib-2.023-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Compress-Zlib-2.020-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Digest-SHA-5.47-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-ExtUtils-CBuilder-0.27-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-ExtUtils-Embed-1.28-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-ExtUtils-MakeMaker-6.55-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-ExtUtils-ParseXS-2.2003.0-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-File-Fetch-0.26-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-IO-Compress-Base-2.020-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-IO-Compress-Zlib-2.020-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-IO-Zlib-1.09-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-IPC-Cmd-0.56-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Locale-Maketext-Simple-0.18-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Log-Message-0.02-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Log-Message-Simple-0.04-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Module-Build-0.3500-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Module-CoreList-2.18-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Module-Load-0.16-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Module-Load-Conditional-0.30-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Module-Loaded-0.02-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Module-Pluggable-3.90-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Object-Accessor-0.34-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Package-Constants-0.02-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Params-Check-0.26-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Parse-CPAN-Meta-1.40-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Pod-Escapes-1.04-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Pod-Simple-3.13-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Term-UI-0.20-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Test-Harness-3.17-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Test-Simple-0.92-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Time-HiRes-1.9721-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-Time-Piece-1.15-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-core-5.10.1-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-debuginfo-5.10.1-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-devel-5.10.1-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-libs-5.10.1-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-parent-0.221-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-suidperl-5.10.1-119.el6", release:'RHEL6') ) flag ++;
if ( rpm_check( reference:"perl-version-0.77-119.el6", release:'RHEL6') ) flag ++;
if (flag)
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
