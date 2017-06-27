#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-237.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74936);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2013-0208", "CVE-2013-0212", "CVE-2013-0247", "CVE-2013-0282", "CVE-2013-0335", "CVE-2013-1664", "CVE-2013-1665", "CVE-2013-1838", "CVE-2013-1840");

  script_name(english:"openSUSE Security Update : openstack (openSUSE-2013-237)");
  script_summary(english:"Check for the openSUSE-2013-237 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Openstack Stack components were updated to Folsom level as of
March 5th.

Changes in openstack-cinder :

  - Update 12.3 packages to Folsom as of March 5th. This
    comes with security fixes and bug fixes that we need to
    have OpenStack work nicely. Fix bnc#802278.

  - Update cinder-config-update.diff: update
    etc/cinder/api-paste.ini to have a signing_dir key under
    [filter:authtoken]. Otherwise, cinder-api won't start.
    This was done with commit de289a6 in Grizzly.

  - Update to version 2012.2.4+git.1362502414.95a620b :

  + Check for non-default volume name template.

  + Fix error for extra specs update with empty body.

  - Update to version 2012.2.4+git.1361527687.68de70d :

  + Add a safe_minidom_parse_string function.
    (CVE-2013-1664)

  - Set auth_strategy to keystone for a good out-of-the-box
    experience

  - Add cinder-config-update.diff: move configuration
    changes to a patch, instead of using sed.

  - Update to version 2012.2.4+git.1360133755.a8caa79 :

  + Final versioning for 2012.2.3

  + Bump version to 2012.2.4

  + Fix typo in cinder/db/api.py

  - Update to version 2012.2.3+git.1358429029.cdf6c13 :

  + Add commands used by NFS volume driver to rootwrap

Changes in openstack-dashboard :

  - Update 12.3 packages to Folsom as of March 5th. This
    comes with security fixes and bug fixes that we need to
    have OpenStack work nicely. Fix bnc#802278.

  - Backport packaging changes we did for Grizzly to fix
    theming :

  + define a production %bcond_with that will determine
    whether offline compression is used or not.

  + if not using the production feature, have a nodejs
    Requires.

  + move compression steps to %prep.

  + by default, use the non-production mode for greater
    flexibility.

  - Do not use 'SUSE Cloud' as site branding: this is not
    SUSE Cloud.

  - Update to version 2012.2.4+git.1362503968.8ece3c7 :

  + pin django to 1.4.x stream

  - Update to version 2012.2.4+git.1361527741.0a42fa0 :

  + Prevent the user from creating a single IP address sized
    network

  + Add UTC offset information to the timezone

  - Update to version 2012.2.4+git.1360133827.f421145 :

  + Final versioning for 2012.2.3

  + Bump version to 2012.2.4

  - Update to version 2012.2.2+git.1359111868.20fa0fc :

  + Pin docutils to 0.9.1, fix pep8 errors

  + Fix bug 1055929 - Can not display usage data for Quota
    Summary.

  + Revert 'Temp fix for api/keystone.py'

  + Specify floating ips table action column's width

  + Allow setting nova quotas to unlimited

  + Add a check for unlimited quotas

  + Avoid cinder calls, when cinder is unavailable

  + Don't inherit from base.html in 500 error page

  + Don't show the EC2 Credentials panel if there is no EC2
    service

  - Drop horizon-ssl.patch: merged upstream.

Changes in openstack-glance :

  - Do not return location in headers (CVE-2013-1840)

  - This fixes bnc#808626.

  - Update 12.3 packages to Folsom as of March 5th. This
    comes with&middot; security fixes and bug fixes that we
    need to have OpenStack work nicely. Fix bnc#802278.

  - Update to version 2012.2.4+git.1362583521.1fb759d :

  + Swallow UserWarning from glance-cache-manage

  + Avoid dangling partial image on size/checksum mismatch

  - Update to version 2012.2.4+git.1362503824.afe6166 :

  + Fix broken JSON schemas in v2 tests

  + Prints list-cached dates in isoformat

  - Update to version 2012.2.4+git.1360133885.98d9928 :

  + Bump version to 2012.2.4

  - Update to version 2012.2.3+git.1359529730.a5b0f4e :

  + Change useexisting to extend_existing to fix deprecation
    warnings.

  + Remove Swift location/password from messages.
    (CVE-2013-0212)

Changes in openstack-keystone :

  - Update 12.3 packages to Folsom as of March 5th. This
    comes with&middot; security fixes and bug fixes that we
    need to have OpenStack work nicely. Fix bnc#802278.

  - fix logging.conf to be about keystone and have absolute
    path

  - Update to version 2012.2.4+git.1362502288.8690166 :

  + Sync timeutils to pick up normalize fix.

  + Backport of fix for 24-hour failure of pki.

  - Update to version 2012.2.4+git.1361527873.37b3532 :

  + Disable XML entity parsing (CVE-2013-1664,
    CVE-2013-1665)

  + Ensure user and tenant enabled in EC2 (CVE-2013-0282)

  - Update to version 2012.2.4+git.1360133921.82c87e5 :

  + Bump version to 2012.2.4

  + Add size validations for /tokens. (CVE-2013-0247)

  - Update to version 2012.2.3+git.1359550485.ec7b94d :

  + Test 0.2.0 keystoneclient to avoid new deps

  + Unparseable endpoint URL's should raise friendly error

  + Fix catalog when services have no URL

  + Render content-type appropriate 404 (bug 1089987)

  - fix last commit's hash tag in Version

Changes in openstack-nova :

  - Add quotas for fixed ips. (CVE-2013-1838)

  - Update to version 2012.2.3+git.1358515929.3545a7d :

  + Add NFS to the libvirt volume driver list

  + Call plug_vifs() for all instances in init_host

  + Fix addition of CPU features when running against legacy
    libvirt

  + Fix typo in resource tracker audit message

  - Move back to 'git_tarballs' source service.

  - Start using obs-service-github_tarballs

  - Update to version 2012.2.3+git.1358434328.a41b913 :

  + Provide better error message for aggregate-create

  + Fix errors in used_limits extension

  + Add an iptables mangle rule per-bridge for DHCP.

  + Limit formatting routes when adding resources

  - Update 12.3 packages to Folsom as of March 5th. This
    comes with&middot; security fixes and bug fixes that we
    need to have OpenStack work nicely. Fix bnc#802278.

  - Install polkit rules file in
    /usr/share/polkit-1/rules.d/ since it's not a
    configuration file, and use 10 instead of 50 as priority
    to make sure it is taken into account.

  - Update to version 2012.2.4+git.1362583574.da38af5 :

  + VNC Token Validation (CVE-2013-0335)

  - Update to version 2012.2.4+git.1362502642.8c4df00 :

  + Ensure we add a new line when appending to rc.local

  + Handle compute node not available for live migration

  + remove intermediate libvirt downloaded images

  - Add openstack-nova-polkit.rules: polkit rules for the
    new polkit that uses JavaScript. On openSUSE 12.3 and
    later, we install this file in /etc/polkit-1/rules.d/
    instead of installing the pkla file which is of no use
    with the new polkit.

  - Update to version 2012.2.4+git.1361527907.d5e7f55 :

  + Avoid stuck task_state on snapshot image failure

  + Add a safe_minidom_parse_string function.
    (CVE-2013-1664)

  + Enable libvirt to work with NoopFirewallDriver

  + Fix state sync logic related to the PAUSED VM state

  + libvirt: Fix nova-compute start when missing ip.

  - Update to version 2012.2.4+git.1360133953.e5d0f4b :

  + Final versioning for 2012.2.3

  + Bump version to 2012.2.4

  - Update to version 2012.2.3+git.1359529791.317cc0a :

  + remove session parameter from fixed_ip_get

  + Eliminate race conditions in floating association

  + Fix to include error message in instance faults

  + disallow boot from volume from specifying arbitrary
    volumes (CVE-2013-0208)

  - Update to version 2012.2.3+git.1359111576.03c3e9b :

  + Ensure that Quantum uses configured fixed IP

  + Makes sure compute doesn't crash on failed resume.

  - Update to version 2012.2.3+git.1358515929.3545a7d :

  + Add NFS to the libvirt volume driver list

  + Call plug_vifs() for all instances in init_host

  + Fix addition of CPU features when running against legacy
    libvirt

  + Fix typo in resource tracker audit message

  - Move back to 'git_tarballs' source service.

  - Start using obs-service-github_tarballs

  - Update to version 2012.2.3+git.1358434328.a41b913 :

  + Provide better error message for aggregate-create

  + Fix errors in used_limits extension

  + Add an iptables mangle rule per-bridge for DHCP.

  + Limit formatting routes when adding resources

Changes in openstack-quantum :

  - Update 12.3 packages to Folsom as of March 5th. This
    comes with&middot; security fixes and bug fixes that we
    need to have OpenStack work nicely. Fix bnc#802278.

  - Update to version 2012.2.4+git.1362583635.f94b149 :

  + L3 port delete prevention: do not raise if no IP on port

  - Update to version 2012.2.4+git.1362504084.06e42f8 :

  + Close file descriptors when executing sub-processes

  + Persist updated expiration time

  - Update to version 2012.2.4+git.1361527969.4de49b4 :

  + only destroy single namespace if router_id is set

  + Enable OVS and NETNS utilities to perform logging

  + Disable dhcp_domain distribution when dhcp_domain is
    empty

  + Shorten the DHCP default resync_interval

  - Update to version 2012.2.4+git.1360134016.d2a85e6 :

  + Final versioning for 2012.2.3

  + Bump version to 2012.2.4

  - Update to version 2012.2.3+git.1359529852.a84ba7e :

  + Regression caused by commit b56c2c998

  + LinuxBridge: update status according to admin_state_up

  + Ensure that correct root helper is used

Changes in openstack-quickstart :

  - Update 12.3 packages to Folsom as of March 5th. This
    comes with&middot; security fixes and bug fixes that we
    need to have OpenStack work nicely. Fix bnc#802278.

  - Update to latest git (cb0fbe8) :

  + Enalbe Cinder and Swift Service endpoints

  + Setup Cinder properly

  - Update to latest git (95d7088) :

  + Fill in values in the cinder/api-paste.ini templatae

Changes in openstack-swift :

  - Update to version 1.7.4.1+git.1359529903.0ce3e1d :

  + Use pypi for python-swiftclient dependency.

  - Update 12.3 packages to Folsom as of March 5th. This
    comes with&middot; security fixes and bug fixes that we
    need to have OpenStack work nicely. Fix bnc#802278.

  - Update to version 1.7.4.1+git.1359529903.0ce3e1d :

  + Use pypi for python-swiftclient dependency.

Changes in python-cinderclient :

  - Update 12.3 packages to Folsom as of March 5th. This
    comes with&middot; security fixes and bug fixes that we
    need to have OpenStack work nicely. Fix bnc#802278.

  - Add compat-newer-requests.patch: take patches from
    upstream to allow working with newer versions of
    python-requests.

Changes in python-django_openstack_auth :

  - Update 12.3 packages to Folsom as of March 5th. This
    comes with&middot; security fixes and bug fixes that we
    need to have OpenStack work nicely. Fix bnc#802278.

  - Update to version 1.0.6 :

  + Fix compatibility with keystoneclient v0.2.

  - Changes from version 1.0.5 :

  + Improves error handling; fixes failing test.

Changes in python-keystoneclient :

  - Update 12.3 packages to Folsom as of March 5th. This
    comes with&middot; security fixes and bug fixes that we
    need to have OpenStack work nicely. Fix bnc#802278.

  - Add compat-newer-requests.patch: take patches from
    upstream to allow working with newer versions of
    python-requests."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808626"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openstack packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-cinder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-cinder-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-cinder-scheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-cinder-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-cinder-volume");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-dashboard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-dashboard-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-glance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-glance-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-keystone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-keystone-test");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-quantum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-quantum-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-quickstart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-swift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-swift-account");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-swift-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-swift-object");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-swift-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-swift-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-cinder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-cinderclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-cinderclient-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-django_openstack_auth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-glance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-horizon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-keystone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-keystoneclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-keystoneclient-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-nova");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-quantum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-swift");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/15");
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

if ( rpm_check(release:"SUSE12.3", reference:"openstack-cinder-2012.2.4+git.1362502414.95a620b-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-cinder-api-2012.2.4+git.1362502414.95a620b-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-cinder-scheduler-2012.2.4+git.1362502414.95a620b-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-cinder-test-2012.2.4+git.1362502414.95a620b-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-cinder-volume-2012.2.4+git.1362502414.95a620b-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-dashboard-2012.2.4+git.1362503968.8ece3c7-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-dashboard-test-2012.2.4+git.1362503968.8ece3c7-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-glance-2012.2.4+git.1363297737.dd849a9-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-glance-test-2012.2.4+git.1363297737.dd849a9-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-keystone-2012.2.4+git.1362502288.8690166-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-keystone-test-2012.2.4+git.1362502288.8690166-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-2012.2.4+git.1363297910.9561484-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-api-2012.2.4+git.1363297910.9561484-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-cert-2012.2.4+git.1363297910.9561484-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-compute-2012.2.4+git.1363297910.9561484-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-network-2012.2.4+git.1363297910.9561484-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-novncproxy-2012.2.4+git.1363297910.9561484-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-objectstore-2012.2.4+git.1363297910.9561484-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-scheduler-2012.2.4+git.1363297910.9561484-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-test-2012.2.4+git.1363297910.9561484-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-vncproxy-2012.2.4+git.1363297910.9561484-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-nova-volume-2012.2.4+git.1363297910.9561484-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-quantum-2012.2.4+git.1362583635.f94b149-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-quantum-test-2012.2.4+git.1362583635.f94b149-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-quickstart-2012.2+git.1360262230.cb0fbe8-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-swift-1.7.4.1+git.1359529903.0ce3e1d-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-swift-account-1.7.4.1+git.1359529903.0ce3e1d-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-swift-container-1.7.4.1+git.1359529903.0ce3e1d-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-swift-object-1.7.4.1+git.1359529903.0ce3e1d-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-swift-proxy-1.7.4.1+git.1359529903.0ce3e1d-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"openstack-swift-test-1.7.4.1+git.1359529903.0ce3e1d-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-cinder-2012.2.4+git.1362502414.95a620b-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-cinderclient-1.0.1.5.g82e47d0+git.1355912775.82e47d0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-cinderclient-test-1.0.1.5.g82e47d0+git.1355912775.82e47d0-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-django_openstack_auth-1.0.6-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-glance-2012.2.4+git.1363297737.dd849a9-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-horizon-2012.2.4+git.1362503968.8ece3c7-2.5.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-keystone-2012.2.4+git.1362502288.8690166-3.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-keystoneclient-0.2.1.3.gd37a3fb+git.1357543650.d37a3fb-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-keystoneclient-test-0.2.1.3.gd37a3fb+git.1357543650.d37a3fb-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-nova-2012.2.4+git.1363297910.9561484-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-quantum-2012.2.4+git.1362583635.f94b149-2.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"python-swift-1.7.4.1+git.1359529903.0ce3e1d-2.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openstack");
}
