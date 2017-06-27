#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2066. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87043);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/06 16:01:53 $");

  script_cve_id("CVE-2015-5245");
  script_osvdb_id(127333);
  script_xref(name:"RHSA", value:"2015:2066");

  script_name(english:"RHEL 7 : Red Hat Ceph Storage 1.3.1 (RHSA-2015:2066)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Red Hat Ceph Storage 1.3.1 that fixes one security issue, multiple
bugs, and adds various enhancements is now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Red Hat Ceph Storage is a massively scalable, open, software-defined
storage platform that combines the most stable version of the Ceph
storage system with a Ceph management platform, deployment tools, and
support services.

A feature in Ceph Object Gateway (RGW) allows to return a specific
HTTP header that contains the name of a bucket that was accessed. It
was found that the returned HTTP headers were not sanitized. An
unauthenticated attacker could use this flaw to craft HTTP headers in
responses that would confuse the load balancer residing in front of
RGW, potentially resulting in a denial of service. (CVE-2015-5245)

The ceph packages have been upgraded to upstream version 0.94.3 and
the radosgw-agent packages have been upgraded to upstream version
1.2.3. The new versions provide a number of bug fixes and enhancements
over the previous versions. (BZ#1238415)

This update also fixes the following bugs :

* This update fixes various bugs in the Ceph monitor nodes and the
Ceph Object Storage Device (OSD) Daemons. (BZ#1219040, BZ#1223941,
BZ#1265973)

* With this update, when using the Civetweb server, the Ceph Object
Gateway no longer reports the full object size downloaded even though
the download was aborted in the middle. (BZ#1235845)

* The Civetweb server now correctly displays the HTTP return code in
the log files. (BZ#1245663)

* The Ceph Object Gateway now correctly assigns Access Control Lists
(ACL) to new objects created during the copy operation. (BZ#1253766)

* Under certain circumstances, copying an object onto itself (for
example, to change its metadata) produced a truncated object. The
truncated object had correct metadata, including the original size,
but the underlying RADOS object was smaller. Consequently, when a
client attempted to fetch the object, it received less data than
indicated by the Content-Length header, blocked for more, and
eventually timed out. This bug has been fixed, and the object can now
be read successfully in the aforementioned scenario. (BZ#1258618)

* The Ceph Object Gateway no longer requires the 'requiretty' setting
to be disabled in the sudoers configuration for the root user.
(BZ#1238521)

* In certain scenarios, when all acting set Ceph Object Storage Device
(OSD) Daemons for a placement group (PG) were restarted during the
backfill process, the OSDs failed to peer the PG. Now, the OSDs peer
the PGs as expected. (BZ#1223532)

In addition, this update adds the following enhancements :

* Administrators of the Ceph Object Gateway can now configure the
maximum number of buckets for users by using the new
'rgw_user_max_buckets' option in the Ceph configuration file.
(BZ#1254343)

* The suicide timeout option is now configurable. The option ensures
that poorly behaving OSDs self-terminate instead of running in
degraded states and slowing traffic. (BZ#1210825)

* The rhcs-installer package provides a new Foreman-based installer.
This update adds the new rhcs-installer package to Red Hat Ceph
Storage as a Technology Preview. (BZ#1213026, BZ#1213086, BZ#1220961)

More information about Red Hat Technology Previews is available here:
https://access.redhat.com/support/offerings/techpreview/

All Red Hat Ceph Storage users are advised to upgrade to this new
version, which corrects these issues and adds these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-2066.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-5245.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:babeltrace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:babeltrace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-deploy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-puppet-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ceph-radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:facter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:facter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-release");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hiera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipxe-bootimgs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipxe-roms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipxe-roms-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libbabeltrace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librados2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:librbd1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:lttng-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:lttng-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:lttng-ust");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:lttng-ust-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:radosgw-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhcs-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-augeas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-augeas-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-rgen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-shadow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-shadow-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-facter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-ruby-wrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ancestry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-apipie-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-audited");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-audited-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-bundler_ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-deep_cloneable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fast_gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-foreigner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-foreman_bootdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-friendly_id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-gettext_i18n_rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-gettext_i18n_rails_js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-i18n_data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ldap_fluff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-multi_json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-net-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-oauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger-native-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-pg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-po_to_json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rabl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rest-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ruby2ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ruby_parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-safemode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-scoped_search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-secure_headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-sexp_processor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-sprockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-uuidtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-validates_lengths_from_database");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-will_paginate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ansi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-apipie-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-awesome_print");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bundler_ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-clamp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ffi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hashie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-highline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-kafo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-kafo_parsers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-little-plugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mime-types");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-multi_json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-oauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-native-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-powerbar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack-protection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rest-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rkerberos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rkerberos-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rubyipmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sinatra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-tilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:userspace-rcu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:userspace-rcu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:2066";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"babeltrace-1.2.4-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"babeltrace-debuginfo-1.2.4-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-common-0.94.3-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-debuginfo-0.94.3-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ceph-deploy-1.5.27.3-1.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ceph-puppet-modules-0.1.1-1.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ceph-radosgw-0.94.3-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"facter-1.7.6-2.1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"facter-debuginfo-1.7.6-2.1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-1.7.2.33-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-debug-1.7.2.33-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-installer-1.7.5-2.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-postgresql-1.7.2.33-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-proxy-1.7.2.5-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-release-1.7.2.33-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-selinux-1.7.2.13-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"foreman-sqlite-1.7.2.33-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"hiera-1.3.1-2.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ipxe-bootimgs-20130517-7.1fm.gitc4bce43.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ipxe-roms-20130517-7.1fm.gitc4bce43.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ipxe-roms-qemu-20130517-7.1fm.gitc4bce43.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libbabeltrace-1.2.4-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librados2-0.94.3-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librados2-devel-0.94.3-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librbd1-0.94.3-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"librbd1-devel-0.94.3-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"lttng-tools-2.4.1-1.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"lttng-tools-debuginfo-2.4.1-1.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"lttng-ust-2.4.1-1.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"lttng-ust-debuginfo-2.4.1-1.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"mod_passenger-4.0.18-19.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"puppet-3.6.2-4.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"puppet-server-3.6.2-4.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-rados-0.94.3-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-rbd-0.94.3-3.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", reference:"radosgw-agent-1.2.3-1.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rhcs-installer-0.1.0-1.el7cp")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ruby-augeas-0.5.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ruby-augeas-debuginfo-0.5.0-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby-rgen-0.6.5-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ruby-shadow-1.4.1-21.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ruby-shadow-debuginfo-1.4.1-21.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ruby193-facter-1.6.18-5.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-ruby-wrapper-0.0.2-6.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-ancestry-2.0.0-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-apipie-rails-0.2.5-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-audited-3.0.0-5.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-audited-activerecord-3.0.0-8.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-bundler_ext-0.3.0-6.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-deep_cloneable-2.0.0-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-fast_gettext-0.8.0-13.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-foreigner-1.4.2-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-foreman_bootdisk-4.0.2.13-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-friendly_id-4.0.10.1-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-gettext_i18n_rails-0.10.0-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-gettext_i18n_rails_js-0.0.8-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-i18n_data-0.2.7-5.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-ldap_fluff-0.3.2-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-multi_json-1.8.2-4.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-net-ldap-0.3.1-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-oauth-0.4.7-8.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ruby193-rubygem-passenger-4.0.18-19.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ruby193-rubygem-passenger-debuginfo-4.0.18-19.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ruby193-rubygem-passenger-native-4.0.18-19.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ruby193-rubygem-passenger-native-libs-4.0.18-19.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ruby193-rubygem-pg-0.12.2-10.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ruby193-rubygem-pg-debuginfo-0.12.2-10.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-po_to_json-0.0.7-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-rabl-0.9.0-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-rest-client-1.6.7-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-ruby2ruby-2.0.1-9.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-ruby_parser-3.1.1-15.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-safemode-1.2.1-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-scoped_search-2.7.1-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-secure_headers-1.3.3-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-sexp_processor-4.1.3-7.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-sprockets-2.10.1-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-uuidtools-2.1.3-6.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-validates_lengths_from_database-0.2.0-1.3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"ruby193-rubygem-will_paginate-3.0.2-10.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-ansi-1.4.3-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-apipie-bindings-0.0.11-1.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-awesome_print-1.0.2-12.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-bundler_ext-0.3.0-7.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-clamp-0.6.2-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-ffi-1.4.0-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-ffi-debuginfo-1.4.0-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-gssapi-1.1.2-4.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-hashie-2.0.5-2.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-highline-1.6.21-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-kafo-0.6.5.9-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-kafo_parsers-0.0.4.4-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-little-plugger-1.1.3-17.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-logging-1.8.1-26.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-mime-types-1.19-7.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-multi_json-1.8.2-4.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-oauth-0.4.7-8.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-passenger-4.0.18-19.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-passenger-debuginfo-4.0.18-19.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-passenger-native-4.0.18-19.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-passenger-native-libs-4.0.18-19.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-powerbar-1.0.11-8.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rack-1.4.1-13.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rack-protection-1.5.0-7.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rake-0.9.2.2-41.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rest-client-1.6.7-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-rkerberos-0.1.2-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"rubygem-rkerberos-debuginfo-0.1.2-3.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-rubyipmi-0.10.0-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-sinatra-1.3.6-27.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-smart_proxy_discovery-1.0.2.1-1.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", reference:"rubygem-tilt-1.3.3-18.el7sat")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"userspace-rcu-0.7.9-2.el7rhgs")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"userspace-rcu-debuginfo-0.7.9-2.el7rhgs")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "babeltrace / babeltrace-debuginfo / ceph-common / ceph-debuginfo / etc");
  }
}
