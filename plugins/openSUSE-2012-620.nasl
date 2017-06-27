#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-620.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74760);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-4600");
  script_osvdb_id(85074);

  script_name(english:"openSUSE Security Update : otrs (openSUSE-SU-2012:1214-1)");
  script_summary(english:"Check for the openSUSE-2012-620 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - fix a XSS vulnerability: bnc#778655 (CVE-2012-4600)

  - update to 2.4.14 (openSUSE 11.4) (fix for OSA-2012-02,
    http://otrs.org/advisory/)

  - Improved HTML security filter to detect tag nesting.

  - update to 3.0.16 (openSUSE 12.1) (fix for OSA-2012-02,
    http://otrs.org/advisory/)

  - Improved HTML security filter to detect tag nesting.

  - Bug#8611 - Ticket count is wrong in QueueView.

  - update to 3.1.10 (openSUSE 12.2) (fix for OSA-2012-02,
    http://otrs.org/advisory/)

  - Improved HTML security filter to detect tag nesting.

  - Bug#8611 - Ticket count is wrong in QueueView.

  - Bug#8698 - Layout.pm only looks at first entry from
    HTTP_ACCEPT_LANGUAGE to determine language.

  - Bug#8731 - LDAP group check returns wrong error."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-09/msg00079.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://otrs.org/advisory/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=778655"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected otrs packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:otrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:otrs-itsm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/11");
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
if (release !~ "^(SUSE11\.4|SUSE12\.1|SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4 / 12.1 / 12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"otrs-2.4.14-14.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"otrs-itsm-2.1.5-14.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"otrs-3.0.16-15.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"otrs-itsm-3.0.6-15.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"otrs-3.1.10-20.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"otrs-itsm-3.1.6-20.8.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "otrs / otrs-itsm");
}
