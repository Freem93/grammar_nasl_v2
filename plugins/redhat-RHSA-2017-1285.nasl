#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1285. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100454);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/26 15:15:35 $");

  script_cve_id("CVE-2017-7401");
  script_xref(name:"RHSA", value:"2017:1285");

  script_name(english:"RHEL 7 : collectd (RHSA-2017:1285)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for collectd is now available for RHEV 4.X RHEV-H and Agents
for RHEL-7 and RHEV Engine version 4.1.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

collectd is a small C-language daemon, which reads various system
metrics periodically and updates RRD files (creating them if
necessary). Because the daemon does not start up each time it updates
files, it has a low system footprint.

The following packages have been upgraded to a newer upstream version:
collectd (5.7.1). (BZ#1446472)

Security Fix(es) :

* collectd contains an infinite loop due to how the parse_packet() and
parse_part_sign_sha256() functions interact. If an instance of
collectd is configured with 'SecurityLevel None' and with empty
'AuthFile' options an attacker can send crafted UDP packets that
trigger the infinite loop, causing a denial of service.
(CVE-2017-7401)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2017-7401.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-1285.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-ascent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-chrony");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-curl_json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-curl_xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-dbi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-drbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-generic-jmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-hugepages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-ipmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-iptables");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-ipvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-log_logstash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-lvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-netlink");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-notify_desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-notify_email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-openldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-rrdcached");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-rrdtool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-sensors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-smart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-turbostat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-virt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-write_http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-write_riemann");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-write_sensu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-write_tsdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:collectd-zookeeper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcollectdclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcollectdclient-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:1285";
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
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-apache-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-ascent-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-bind-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-ceph-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-chrony-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-curl-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-curl_json-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-curl_xml-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-dbi-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-disk-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-dns-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-drbd-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-email-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-generic-jmx-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-hugepages-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-ipmi-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-iptables-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-ipvs-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-java-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-log_logstash-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-lvm-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-mysql-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-netlink-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-nginx-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-notify_desktop-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-notify_email-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-openldap-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-ping-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-postgresql-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-rrdcached-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-rrdtool-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-sensors-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-smart-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-snmp-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-turbostat-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-utils-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-virt-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-write_http-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-write_riemann-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-write_sensu-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-write_tsdb-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"collectd-zookeeper-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcollectdclient-5.7.1-4.el7")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcollectdclient-devel-5.7.1-4.el7")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "collectd / collectd-apache / collectd-ascent / collectd-bind / etc");
  }
}


