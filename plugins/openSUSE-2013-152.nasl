#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-152.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74900);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2012-6109", "CVE-2013-0183", "CVE-2013-0184", "CVE-2013-0262", "CVE-2013-0263", "CVE-2013-0276", "CVE-2013-0277");
  script_osvdb_id(89317, 89320, 89327, 89938, 89939, 90072, 90073);

  script_name(english:"openSUSE Security Update : RubyOnRails (openSUSE-SU-2013:0338-1)");
  script_summary(english:"Check for the openSUSE-2013-152 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Ruby on Rails 2.3 stack was updated to 2.3.17. The Ruby on Rails
3.2 stack was updated to 3.2.12.

The Ruby Rack was updated to 1.1.6. The Ruby Rack was
updated to 1.2.8. The Ruby Rack was updated to 1.3.10. The
Ruby Rack was updated to 1.4.5.

The updates fix various security issues and bugs.

  - update to version 2.3.17 (bnc#803336, bnc#803339)
    CVE-2013-0276 CVE-2013-0277 :

  - update to version 3.2.12 (bnc#803336) CVE-2013-0276 :

  - update to version 3.2.12 (bnc#803336) CVE-2013-0276:
    issue with attr_protected where malformed input could
    circumvent protection

  - update to version 2.3.17 (bnc#803336, bnc#803339)
    CVE-2013-0276 CVE-2013-0277 :

  - Fix issue with attr_protected where malformed input
    could circumvent protection

  - Fix Serialized Attributes YAML Vulnerability

  - update to version 2.3.17 (bnc#803336, bnc#803339)
    CVE-2013-0276 CVE-2013-0277 :

  - Fix issue with attr_protected where malformed input
    could circumvent protection

  - Fix Serialized Attributes YAML Vulnerability

  - update to version 3.2.12 (bnc#803336) CVE-2013-0276 :

  - Quote numeric values being compared to non-numeric
    columns. Otherwise, in some database, the string column
    values will be coerced to a numeric allowing 0, 0.0 or
    false to match any string starting with a non-digit.

  - update to 1.1.6 (bnc#802794)

  - Fix CVE-2013-0263, timing attack against
    Rack::Session::Cookie

  - update to 1.2.8 (bnc#802794)

  - Fix CVE-2013-0263, timing attack against
    Rack::Session::Cookie

  - update to 1.3.10 (bnc#802794)

  - Fix CVE-2013-0263, timing attack against
    Rack::Session::Cookie

  - ruby rack update to 1.4.5 (bnc#802794 bnc#802795)

  - Fix CVE-2013-0263, timing attack against
    Rack::Session::Cookie

  - Fix CVE-2013-0262, symlink path traversal in Rack::File

  - ruby rack update to 1.4.4 (bnc#798452)

  - [SEC] Rack::Auth::AbstractRequest no longer symbolizes
    arbitrary strings (CVE-2013-0184)

  - ruby rack changes from 1.4.3

  - Security: Prevent unbounded reads in large multipart
    boundaries (CVE-2013-0183)

  - ruby rack changes from 1.4.2 (CVE-2012-6109)

  - Add warnings when users do not provide a session secret

  - Fix parsing performance for unquoted filenames

  - Updated URI backports

  - Fix URI backport version matching, and silence constant
    warnings

  - Correct parameter parsing with empty values

  - Correct rackup '-I' flag, to allow multiple uses

  - Correct rackup pidfile handling

  - Report rackup line numbers correctly

  - Fix request loops caused by non-stale nonces with time
    limits

  - Fix reloader on Windows

  - Prevent infinite recursions from Response#to_ary

  - Various middleware better conforms to the body close
    specification

  - Updated language for the body close specification

  - Additional notes regarding ECMA escape compatibility
    issues

  - Fix the parsing of multiple ranges in range headers

  - Prevent errors from empty parameter keys

  - Added PATCH verb to Rack::Request

  - Various documentation updates

  - Fix session merge semantics (fixes rack-test)

  - Rack::Static :index can now handle multiple directories

  - All tests now utilize Rack::Lint (special thanks to Lars
    Gierth)

  - Rack::File cache_control parameter is now deprecated,
    and removed by 1.5

  - Correct Rack::Directory script name escaping

  - Rack::Static supports header rules for sophisticated
    configurations

  - Multipart parsing now works without a Content-Length
    header

  - New logos courtesy of Zachary Scott!

  - Rack::BodyProxy now explicitly defines #each, useful for
    C extensions

  - Cookies that are not URI escaped no longer cause
    exceptions"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-02/msg00071.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=798452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=803336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=803339"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected RubyOnRails packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-actionmailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-actionmailer-2_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-actionmailer-2_3-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-actionmailer-3_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-actionpack-2_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-actionpack-2_3-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-actionpack-3_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activemodel-3_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activerecord-2_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activerecord-2_3-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activerecord-3_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activeresource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activeresource-2_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activeresource-2_3-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activeresource-3_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activesupport-2_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activesupport-3_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-rack-1_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-rack-1_1-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-rack-1_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-rack-1_2-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-rack-1_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-rack-1_3-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-rack-1_4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-rack-1_4-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-rails-2_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-rails-3_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-railties-3_2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"rubygem-actionmailer-2.3.17-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-actionmailer-2_3-2.3.17-3.13.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-actionmailer-2_3-testsuite-2.3.17-3.13.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-actionpack-2.3.17-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-actionpack-2_3-2.3.17-3.20.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-actionpack-2_3-testsuite-2.3.17-3.20.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activerecord-2.3.17-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activerecord-2_3-2.3.17-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activerecord-2_3-testsuite-2.3.17-3.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activeresource-2.3.17-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activeresource-2_3-2.3.17-3.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activeresource-2_3-testsuite-2.3.17-3.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activesupport-2.3.17-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activesupport-2_3-2.3.17-3.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-rack-1_1-1.1.6-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-rack-1_1-testsuite-1.1.6-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-rails-2.3.17-2.11.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-rails-2_3-2.3.17-3.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-actionmailer-2.3.17-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-actionmailer-2_3-2.3.17-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-actionmailer-2_3-testsuite-2.3.17-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-actionmailer-3_2-3.2.12-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-actionpack-2.3.17-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-actionpack-2_3-2.3.17-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-actionpack-2_3-testsuite-2.3.17-2.17.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-actionpack-3_2-3.2.12-3.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activemodel-3_2-3.2.12-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activerecord-2.3.17-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activerecord-2_3-2.3.17-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activerecord-2_3-testsuite-2.3.17-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activerecord-3_2-3.2.12-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activeresource-2.3.17-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activeresource-2_3-2.3.17-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activeresource-2_3-testsuite-2.3.17-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activeresource-3_2-3.2.12-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activesupport-2.3.17-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activesupport-2_3-2.3.17-3.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activesupport-3_2-3.2.12-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rack-1_1-1.1.6-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rack-1_1-testsuite-1.1.6-6.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rack-1_2-1.2.8-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rack-1_2-testsuite-1.2.8-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rack-1_3-1.3.10-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rack-1_3-testsuite-1.3.10-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rack-1_4-1.4.5-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rack-1_4-testsuite-1.4.5-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rails-2.3.17-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rails-2_3-2.3.17-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rails-3_2-3.2.12-2.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-railties-3_2-3.2.12-2.13.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "RubyOnRails");
}
