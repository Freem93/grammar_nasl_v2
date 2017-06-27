#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-510.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(77318);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/08/22 14:01:55 $");

  script_name(english:"openSUSE Security Update : - Update to version neutron-2013.2.4.dev84.gbe0c1d1 (openSUSE-SU-2014:1051-1)");
  script_summary(english:"Check for the openSUSE-2014-510 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Update to version neutron-2013.2.4.dev84.gbe0c1d1 :

  - Fix get_vif_port_by_id to only return relevant ports

  - Update to version neutron-2013.2.4.dev82.gd1a9a9d :

  - LBaaS add missing rootwrap filter for route

  - NVP plugin:fix delete sec group when backend is out of
    sync

  - Kill 'Skipping unknown group key: firewall_driver' log
    trace

  - Update to version neutron-2013.2.4.dev76.g0397e59 :

  - Added missing plugin .ini files to setup.cfg

  - Update to version neutron-2013.2.4.dev75.g1859a5a :

  - OVS lib defer apply doesn't handle concurrency

  - Fixed floating IP logic in PLUMgrid plugin

  - tests/unit: Initialize core plugin in TestL3GwModeMixin

  - Update to version neutron-2013.2.4.dev69.ge5fed48 :

  - Install SNAT rules for ipv4 only

  - Update to version neutron-2013.2.4.dev68.ge075c5f :

  - Optionally delete namespaces when they are no longer
    needed

  - Update to version neutron-2013.2.4.dev66.g208667b :

  - l2-population : send flooding entries when the last port
    goes down

  - l2-population/lb/vxlan : ip neigh add command failed

  - Update to version neutron-2013.2.4.dev62.g93a43a6 :

  - Fixes the Hyper-V agent individual ports metrics

  - Update to version neutron-2013.2.4.dev60.ge312dc7 :"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-08/msg00035.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=874757"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected - Update to version neutron-2013.2.4.dev84.gbe0c1d1 packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-neutron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-neutron-dhcp-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-neutron-ha-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-neutron-hyperv-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-neutron-l3-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-neutron-lbaas-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-neutron-linuxbridge-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-neutron-metadata-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-neutron-metering-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-neutron-mlnx-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-neutron-nec-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-neutron-openvswitch-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-neutron-plugin-cisco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-neutron-ryu-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-neutron-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-neutron-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-neutron-vmware-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-neutron-vpn-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-eventlet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-greenlet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-greenlet-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-greenlet-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-greenlet-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-iso8601");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-neutron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-neutronclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-neutronclient-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-pytest");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/22");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"openstack-neutron-2013.2.4.dev86.gb4b09a6-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openstack-neutron-dhcp-agent-2013.2.4.dev86.gb4b09a6-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openstack-neutron-ha-tool-2013.2.4.dev86.gb4b09a6-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openstack-neutron-hyperv-agent-2013.2.4.dev86.gb4b09a6-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openstack-neutron-l3-agent-2013.2.4.dev86.gb4b09a6-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openstack-neutron-lbaas-agent-2013.2.4.dev86.gb4b09a6-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openstack-neutron-linuxbridge-agent-2013.2.4.dev86.gb4b09a6-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openstack-neutron-metadata-agent-2013.2.4.dev86.gb4b09a6-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openstack-neutron-metering-agent-2013.2.4.dev86.gb4b09a6-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openstack-neutron-mlnx-agent-2013.2.4.dev86.gb4b09a6-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openstack-neutron-nec-agent-2013.2.4.dev86.gb4b09a6-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openstack-neutron-openvswitch-agent-2013.2.4.dev86.gb4b09a6-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openstack-neutron-plugin-cisco-2013.2.4.dev86.gb4b09a6-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openstack-neutron-ryu-agent-2013.2.4.dev86.gb4b09a6-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openstack-neutron-server-2013.2.4.dev86.gb4b09a6-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openstack-neutron-test-2013.2.4.dev86.gb4b09a6-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openstack-neutron-vmware-agent-2013.2.4.dev86.gb4b09a6-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openstack-neutron-vpn-agent-2013.2.4.dev86.gb4b09a6-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-eventlet-0.14.0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-greenlet-0.4.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-greenlet-debuginfo-0.4.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-greenlet-debugsource-0.4.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-greenlet-devel-0.4.2-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-iso8601-0.1.10-6.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-neutron-2013.2.4.dev86.gb4b09a6-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-neutronclient-2.3.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-neutronclient-test-2.3.4-6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-py-1.4.22-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-pytest-2.6.0-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "- Update to version neutron-2013.2.4.dev84.gbe0c1d1");
}
