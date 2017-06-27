#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-210.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75292);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2013-6172");
  script_bugtraq_id(63300);

  script_name(english:"openSUSE Security Update : roundcubemail (openSUSE-SU-2014:0365-1)");
  script_summary(english:"Check for the openSUSE-2014-210 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"roundcubemail was updated to 0.9.5 to fix bugs and security issues.

Fixed security issues :

  - CVE-2013-6172: vulnerability in handling _session
    argument of utils/save-prefs

New upstream release 0.9.5 (bnc#847179) (CVE-2013-6172)

  - Fix failing vCard import when email address field
    contains spaces

  - Fix default spell-check configuration after Google
    suspended their spell service

  - Fix vulnerability in handling _session argument of
    utils/save-prefs

  - Fix iframe onload for upload errors handling

  - Fix address matching in Return-Path header on identity
    selection

  - Fix text wrapping issue with long unwrappable lines

  - Fixed mispelling: occured -> occurred

  - Fixed issues where HTML comments inside style tag would
    hang Internet Explorer

  - Fix setting domain in virtualmin password driver

  - Hide Delivery Status Notification option when
    smtp_server is unset

  - Display full attachment name using title attribute when
    name is too long to display

  - Fix attachment icon issue when rare font/language is
    used

  - Fix expanded thread root message styling after
    refreshing messages list

  - Fix issue where From address was removed from Cc and Bcc
    fields when editing a draft

  - Fix error_reporting directive check

  - Fix de_DE localization of 'About' label in Help plugin"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-03/msg00035.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=847179"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected roundcubemail packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:php5-pear-Net_IDNA2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:roundcubemail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"php5-pear-Net_IDNA2-0.1.1-5.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"roundcubemail-0.9.5-1.18.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"php5-pear-Net_IDNA2-0.1.1-5.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"roundcubemail-0.9.5-2.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "roundcubemail");
}
