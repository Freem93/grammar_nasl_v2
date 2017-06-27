#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-162.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(81417);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/11 13:51:32 $");

  script_cve_id("CVE-2012-1152", "CVE-2013-6393", "CVE-2014-2525", "CVE-2014-9130");

  script_name(english:"openSUSE Security Update : perl-YAML-LibYAML (openSUSE-2015-162)");
  script_summary(english:"Check for the openSUSE-2015-162 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"perl-YAML-LibYAML was updated to version 0.59 to fix four security
issues.

These security issues were fixed :

  - CVE-2013-6393: The yaml_parser_scan_tag_uri function in
    scanner.c in LibYAML before 0.1.5 performs an incorrect
    cast, which allowed remote attackers to cause a denial
    of service (application crash) and possibly execute
    arbitrary code via crafted tags in a YAML document,
    which triggers a heap-based buffer overflow (bnc#860617,
    bnc#911782).

  - CVE-2012-1152: Multiple format string vulnerabilities in
    the error reporting functionality in the YAML::LibYAML
    (aka YAML-LibYAML and perl-YAML-LibYAML) module 0.38 for
    Perl allowed remote attackers to cause a denial of
    service (process crash) via format string specifiers in
    a (1) YAML stream to the Load function, (2) YAML node to
    the load_node function, (3) YAML mapping to the
    load_mapping function, or (4) YAML sequence to the
    load_sequence function (bnc#751503).

  - CVE-2014-9130: scanner.c in LibYAML 0.1.5 and 0.1.6, as
    used in the YAML-LibYAML (aka YAML-XS) module for Perl,
    allowed context-dependent attackers to cause a denial of
    service (assertion failure and crash) via vectors
    involving line-wrapping (bnc#907809, bnc#911782).

  - CVE-2014-2525: Heap-based buffer overflow in the
    yaml_parser_scan_uri_escapes function in LibYAML before
    0.1.6 allowed context-dependent attackers to execute
    arbitrary code via a long sequence of percent-encoded
    characters in a URI in a YAML file (bnc#868944,
    bnc#911782).

These non-security issues were fixed :

  - PR/23 Better scalar dump heuristics

  - More closely match YAML.pm

  - Add a VERSION statement to YAML::LibYAML (issue#8)

  - Applied fix for PR/21. nawglan++

  - Use Swim cpan-tail block functions in doc

  - Get YAML::XS using latest libyaml

  - Fix for
    https://bitbucket.org/xi/libyaml/issue/10/wrapped-string
    s-cause-assert-failure

  - Fix e1 test failure on 5.21.4

  - Remove =travis section

  - Meta 0.0.2

  - Eliminate spurious trailing whitespace

  - Add t/000-compile-modules.t

  - Fix swim errors

  - Add badges to doc

  - Fix ReadMe

  - Fix Meta and add Contributing.

  - Doc fix. GitHub-Issue-#6. Thanks to Debian Perl Group
    for finding this.

  - Test::Base tests needed 'inc' in @INC

  - Switch to Zilla::Dist

  - No longer dep on Test::Base, Spiffy, and
    Filter::Util::Call

  - Remove test/changes.t

  - Removed another C++ // style comment. jdb++

  - Removed C++ // style comments, for better portability.
    jdb++

  - Using the latest libyaml codebase

- https://github.com/yaml/libyaml/tree/perl-yaml-xs

  - Changes have been made to start moving libyaml to 1.2"
  );
  # https://bitbucket.org/xi/libyaml/issue/10/wrapped-strings-cause-assert-failure
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82d71510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=751503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=860617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=868944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=907809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=911782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/yaml/libyaml/tree/perl-yaml-xs"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected perl-YAML-LibYAML packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-YAML-LibYAML");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-YAML-LibYAML-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-YAML-LibYAML-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"perl-YAML-LibYAML-0.59-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"perl-YAML-LibYAML-debuginfo-0.59-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"perl-YAML-LibYAML-debugsource-0.59-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"perl-YAML-LibYAML-0.59-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"perl-YAML-LibYAML-debuginfo-0.59-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"perl-YAML-LibYAML-debugsource-0.59-2.4.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-YAML-LibYAML / perl-YAML-LibYAML-debuginfo / etc");
}
