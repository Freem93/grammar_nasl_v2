#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-539.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75061);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-2030");

  script_name(english:"openSUSE Security Update : openstack-nova (openSUSE-SU-2013:1087-1)");
  script_summary(english:"Check for the openSUSE-2013-539 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of openstack-nova fixes a security vulnerability.

  - Add CVE-2013-2030.patch: fix insecure keystone
    middleware tmpdir by default (CVE-2013-2030,
    bnc#819349).

  - Use explicit keystone-signing dir to workaround
    lp#1181157."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00197.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819349"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openstack-nova packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-nova");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-nova-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-nova-cert");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-nova-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-nova-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-nova-novncproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-nova-objectstore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-nova-scheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-nova-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-nova-vncproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-nova-volume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-greenlet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-greenlet-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-greenlet-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-greenlet-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-nova");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/20");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-2012.2.4+git.1363297910.9561484-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-api-2012.2.4+git.1363297910.9561484-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-cert-2012.2.4+git.1363297910.9561484-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-compute-2012.2.4+git.1363297910.9561484-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-network-2012.2.4+git.1363297910.9561484-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-novncproxy-2012.2.4+git.1363297910.9561484-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-objectstore-2012.2.4+git.1363297910.9561484-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-scheduler-2012.2.4+git.1363297910.9561484-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-test-2012.2.4+git.1363297910.9561484-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-vncproxy-2012.2.4+git.1363297910.9561484-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-volume-2012.2.4+git.1363297910.9561484-2.10.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-greenlet-0.4.0-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-greenlet-debuginfo-0.4.0-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-greenlet-debugsource-0.4.0-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-greenlet-devel-0.4.0-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-nova-2012.2.4+git.1363297910.9561484-2.10.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openstack-nova / openstack-nova-api / openstack-nova-cert / etc");
}
