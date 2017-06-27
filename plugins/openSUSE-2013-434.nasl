#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-434.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75006);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:13 $");

  script_cve_id("CVE-2013-2059");

  script_name(english:"openSUSE Security Update : openstack-keystone (openSUSE-SU-2013:0949-1)");
  script_summary(english:"Check for the openSUSE-2013-434 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenStack Keystone was updated to fix (bnc#818596, CVE-2013-2059):
Keystone tokens not immediately invalidated when user is deleted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00085.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818596"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openstack-keystone packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-keystone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-keystone-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-keystone");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"openstack-keystone-2012.2.4+git.1363796849.255b1d4-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-keystone-test-2012.2.4+git.1363796849.255b1d4-3.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-keystone-2012.2.4+git.1363796849.255b1d4-3.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openstack-keystone");
}
