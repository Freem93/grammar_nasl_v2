#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-557.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75074);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-2161");

  script_name(english:"openSUSE Security Update : openstack-swift (openSUSE-SU-2013:1146-1)");
  script_summary(english:"Check for the openSUSE-2013-557 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of openstack-swift fixes a security vulnerability.

  - Add CVE-2013-2161.patch: fix unchecked user input in
    Swift XML responses (CVE-2013-2161, bnc#824286)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-07/msg00021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=824286"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openstack-swift packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-swift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-swift-account");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-swift-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-swift-object");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-swift-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-swift-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-swift");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/22");
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

if ( rpm_check(release:"SUSE12.3", reference:"openstack-swift-1.7.4.1+git.1359529903.0ce3e1d-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-swift-account-1.7.4.1+git.1359529903.0ce3e1d-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-swift-container-1.7.4.1+git.1359529903.0ce3e1d-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-swift-object-1.7.4.1+git.1359529903.0ce3e1d-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-swift-proxy-1.7.4.1+git.1359529903.0ce3e1d-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-swift-test-1.7.4.1+git.1359529903.0ce3e1d-2.8.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-swift-1.7.4.1+git.1359529903.0ce3e1d-2.8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openstack-swift / openstack-swift-account / etc");
}
