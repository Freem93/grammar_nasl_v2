#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-106.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74881);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_cve_id("CVE-2012-2695", "CVE-2012-6496", "CVE-2013-0155", "CVE-2013-0156", "CVE-2013-0333");
  script_osvdb_id(82610, 88661, 89025, 89026, 89064, 89594);

  script_name(english:"openSUSE Security Update : ruby (openSUSE-SU-2013:0278-1)");
  script_summary(english:"Check for the openSUSE-2013-106 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update updates the RubyOnRails 2.3 stack to 2.3.16, also this
update updates the RubyOnRails 3.2 stack to 3.2.11.

Security and bugfixes were done, foremost: CVE-2013-0333: A JSON
sql/code injection problem was fixed. CVE-2012-5664: A SQL Injection
Vulnerability in Active Record was fixed. CVE-2012-2695: A SQL
injection via nested hashes in conditions was fixed. CVE-2013-0155:
Unsafe Query Generation Risk in Ruby on Rails was fixed.
CVE-2013-0156: Multiple vulnerabilities in parameter parsing in Action
Pack were fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-02/msg00030.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=766792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=775653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=796712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=798452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=798458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=800320"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ruby on Rails JSON Processor YAML Deserialization Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-sprockets-2_2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE12.1", reference:"rubygem-actionmailer-2.3.16-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-actionmailer-2_3-2.3.16-3.9.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-actionmailer-2_3-testsuite-2.3.16-3.9.3") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-actionpack-2.3.16-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-actionpack-2_3-2.3.16-3.16.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-actionpack-2_3-testsuite-2.3.16-3.16.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activerecord-2.3.16-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activerecord-2_3-2.3.16-3.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activerecord-2_3-testsuite-2.3.16-3.12.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activeresource-2.3.16-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activeresource-2_3-2.3.16-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activeresource-2_3-testsuite-2.3.16-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activesupport-2.3.16-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-activesupport-2_3-2.3.16-3.13.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-rack-1_1-1.1.5-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-rack-1_1-testsuite-1.1.5-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-rails-2.3.16-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"rubygem-rails-2_3-2.3.16-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-actionmailer-2.3.16-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-actionmailer-2_3-2.3.16-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-actionmailer-2_3-testsuite-2.3.16-2.5.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-actionmailer-3_2-3.2.11-2.9.5") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-actionpack-2.3.16-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-actionpack-2_3-2.3.16-2.13.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-actionpack-2_3-testsuite-2.3.16-2.13.3") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-actionpack-3_2-3.2.11-3.9.4") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activemodel-3_2-3.2.11-2.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activerecord-2.3.16-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activerecord-2_3-2.3.16-2.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activerecord-2_3-testsuite-2.3.16-2.9.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activerecord-3_2-3.2.11-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activeresource-2.3.16-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activeresource-2_3-2.3.16-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activeresource-2_3-testsuite-2.3.16-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activeresource-3_2-3.2.11-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activesupport-2.3.16-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activesupport-2_3-2.3.16-3.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-activesupport-3_2-3.2.11-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rack-1_1-1.1.5-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rack-1_1-testsuite-1.1.5-6.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rack-1_2-1.2.7-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rack-1_2-testsuite-1.2.7-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rack-1_3-1.3.9-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rack-1_3-testsuite-1.3.9-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rack-1_4-1.4.1-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rack-1_4-testsuite-1.4.1-2.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rails-2.3.16-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rails-2_3-2.3.16-3.5.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-rails-3_2-3.2.11-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-railties-3_2-3.2.11-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"rubygem-sprockets-2_2-2.2.2-2.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rubygem-actionmailer-2_3 / rubygem-actionmailer-2_3-testsuite / etc");
}
