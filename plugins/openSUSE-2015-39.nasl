#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-39.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80842);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/20 14:28:12 $");

  script_cve_id("CVE-2013-6858", "CVE-2014-0157", "CVE-2014-3473", "CVE-2014-3474", "CVE-2014-3475", "CVE-2014-3594", "CVE-2014-8124");

  script_name(english:"openSUSE Security Update : openstack-dashboard (openSUSE-SU-2015:0078-1)");
  script_summary(english:"Check for the openSUSE-2015-39 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenStack Dashboard was updated to fix bugs and security issues.

Full changes :

  - Update to version horizon-2013.2.5.dev2.g9ee7273 :

  - fix Horizon login page DOS attack (bnc#908199,
    CVE-2014-8124)

  - update version to 2013.2.5

  - Updated from global requirements

  - Pin docutils to 0.9.1

  - Set python hash seed to 0 in tox.ini

  - Check host is not none in each availability zone

  - Fix XSS issue with the unordered_list filter
    (bnc#891815, CVE-2014-3594)

  + 0001-Use-default_project_id-for-v3-users.patch
    (manually)

  - Replace UserManager with None in tests

  - Update test-requirements to fix sphinx build_doc

  - Fix multiple Cross-Site Scripting (XSS) vulnerabilities
    (bnc#885588, CVE-2014-3473, CVE-2014-3474,
    CVE-2014-3475)

  - Fix issues with importing the Login form

    Bug 869696 - Admin password injection on Horizon
    Dashboard is broken.

  - Update to version horizon-2013.2.4.dev8.g07c097f :

  - Bug fix on neutron's API to return the correct target ID

  - Fix display of images in Rebuild Instance

  - Get instance networking information from Neutron

  - Bump stable/havana next version to 2013.2.4

  - Do not release FIP on disassociate action

  - Introduces escaping in Horizon/Orchestration 2013.2.3
    (bnc#871855, CVE-2014-0157)

  - Update to version horizon-2013.2.3.dev8.g3d04c3c :

  - Reduce number of novaclient calls

  - Don't copy the flavorid when updating flavors

  - Allow snapshots of paused and suspended instances

  - Fixing tests to work with keystoneclient 0.6.0

  - Bump stable/havana next version to 2013.2.3

  + Use upstream URL as source (enables verification)

  + Import translations for Havana 2013.2.2 udpate

  - Update to version 2013.2.2.dev29.g96bd650 :

  + Update Transifex resource name for havana

  + Fix inappropriate logouts on load-balanced Horizon

  - Update to version 2013.2.2.dev25.g6508afd :

  + disable volume creation, when cinder is disabled

  + Bad workflow-steps check: has_required_fields

  + Specify tenant_id when retrieving LBaaS/VPNaaS resource

  - Update to version 2013.2.2.dev19.g7a8eadc :

  + Give HealthMonitor a proper display name

  - Update to version 2013.2.2.dev17.gaa55b24 :

  + Common keystone version fallback

  - Move settings.py (default settings) to branding-upstream
    subpackage: a branding package might want to change some
    default settings.

  - add 0001-Common-keystone-version-fallback.patch,
    0001-Use-default_project_id-for-v3-users.patch

  - Update to version 2013.2.2.dev15.g2b6dfa7 :

  + fix help text in 'Create An image' window

  + Change how scrollShift is calculated

  + unify keypair name handling

  - Add
    0001-Give-no-background-color-to-the-pie-charts.patch:
    do not give a background color to pie charts.

  - Update to version 2013.2.2.dev9.gc6d38a1 :

  + Wrong marker sent to keystone

  - Update to version 2013.2.2.dev7.g2e11482 :

  + Adding management_url to test mock client

  - add
    0001-Bad-workflow-steps-check-has_required_fields.patch 

  - Make python-horizon require the 2013.2 version of
    python-horizon-branding (and not the 2013.2.xyz
    version). This makes it easier to create non-upstream
    branding; we already do this for the other branding
    subpackage.

  - Update to version 2013.2.2.dev6.g2c1f1f3 :

  + Add check for BlockDeviceMappingV2 nova extension

  + Gracefully handle Users with no email attribute

  + Import install_venv from oslo

  + Bump stable/havana next version to 2013.2.2

  - Update to version 2013.2.1.dev41.g9668e80 :

  + Updated from global requirements

  - put everything under /srv/www/openstack-dashboard 

  - Update to version 2013.2.1.dev40.g852e5c8 :

  + Import translations for Havana 2013.2.1 udpate

  + Deleting statistics tables from resource usage page

  + Allow 'Working' in spinner to be translatable

  + lbaas/horizon - adds tcp protocol choice when create lb

  + Fix a bug some optional field in LBaaS are mandatory

  + Fix bug so that escaped html is not shown in volume
    detach dialog

  + Role name should not be translated in Domain Groups
    dialog

  + Fix incomplete translation of 'Update members' widget

  + Fix translatable string for 'Injected File Path Bytes'

  + Add extra extension file to makemessage command line

  + Add contextual markers to BatchAction messages

  + Logging user out after self password change

  + Add logging configuration for iso8601 module

  + Ensure all compute meters are listed in dropdown

  + Fix bug by escaping strings from Nova before displaying
    them (bnc#852175, CVE-2013-6858)

  - add/use generic openstack-branding provides 

  - Update to version 2013.2.1.dev9.g842ba5f :

  + Fix default port of MS SQL in security group template

  + Provide missing hover hints for instance:<type> meters

  + translate text: 'subnet'/'subnet details'

  + Change 'Tenant' to 'Project'

  + Avoid discarding precision of metering data

  - Use Django's signed_cookies session backend like
    upstream and drop the usage of cache_db

  - No need to set SECRET_KEY anymore, upstream learned it
    too

python-django_openstack_auth was updated to 1.1.3 :

  - Various i18n fixes

  - Revoke tokens when logging out or changing the tenant

  - Run tests locally, therefore merge test package back
    into main

  - Properly build HTML documentation and install it

  - Add pt_BR locale

  - Updated (build) requirements

  - Add django_openstack_auth-hacking-requires.patch:
    hacking dep is nonsense

  - include tests runner 

  - add -test subpackage"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2015-01/msg00040.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=852175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=869696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=871855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=885588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=891815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908199"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openstack-dashboard packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-dashboard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-dashboard-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openstack-dashboard-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-django_openstack_auth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-horizon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-horizon-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"openstack-dashboard-2013.2.5.dev2.g9ee7273-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openstack-dashboard-branding-upstream-2013.2.5.dev2.g9ee7273-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openstack-dashboard-test-2013.2.5.dev2.g9ee7273-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-django_openstack_auth-1.1.3-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-horizon-2013.2.5.dev2.g9ee7273-4.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-horizon-branding-upstream-2013.2.5.dev2.g9ee7273-4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openstack-dashboard / openstack-dashboard-branding-upstream / etc");
}
