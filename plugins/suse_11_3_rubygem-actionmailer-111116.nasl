#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update rubygem-actionmailer-5440.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75730);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/02 15:19:31 $");

  script_cve_id("CVE-2010-3933", "CVE-2011-0446", "CVE-2011-0447", "CVE-2011-0448", "CVE-2011-0449", "CVE-2011-2930", "CVE-2011-2931", "CVE-2011-3186");
  script_osvdb_id(68769, 70905, 70906, 70927, 70928, 74614, 74616, 74617);

  script_name(english:"openSUSE Security Update : rubygem-actionmailer (openSUSE-SU-2011:1305-1)");
  script_summary(english:"Check for the rubygem-actionmailer-5440 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of rails fixes the following security issues :

CVE-2011-2930 - SQL-injection in quote_table_name function via
specially crafted column names (bnc#712062) CVE-2011-2931 - Cross-Site
Scripting (XSS) in the strip_tags helper (bnc#712057) CVE-2011-3186 -
Response Splitting (bnc#712058) CVE-2010-3933 - Arbitrary modification
of records via specially crafted form parameters (bnc#712058)
CVE-2011-0446 - Cross-Site Scripting (XSS) in the mail_to helper
(bnc#668817) CVE-2011-0447 - Improper validation of 'X-Requested-With'
header (bnc#668817) CVE-2011-0448 - SQL-injection caused by improperly
sanitized arguments to the limit function (bnc#668817) CVE-2011-0449 -
Bypass of access restrictions via specially crafted action names
(bnc#668817)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-12/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=668817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=712057"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=712058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=712062"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rubygem-actionmailer packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-actionmailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-actionmailer-2_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-actionpack-2_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activerecord-2_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activeresource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activeresource-2_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-activesupport-2_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rubygem-rails-2_3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/16");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"rubygem-actionmailer-2.3.14-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"rubygem-actionmailer-2_3-2.3.14-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"rubygem-actionpack-2.3.14-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"rubygem-actionpack-2_3-2.3.14-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"rubygem-activerecord-2.3.14-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"rubygem-activerecord-2_3-2.3.14-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"rubygem-activeresource-2.3.14-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"rubygem-activeresource-2_3-2.3.14-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"rubygem-activesupport-2.3.14-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"rubygem-activesupport-2_3-2.3.14-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"rubygem-rack-1.1.2-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"rubygem-rails-2.3.14-0.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"rubygem-rails-2_3-2.3.14-0.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rubygem-actionmailer / rubygem-actionmailer-2_3 / etc");
}
