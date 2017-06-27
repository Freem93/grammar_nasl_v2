#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0421. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79284);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/05 16:04:21 $");

  script_cve_id("CVE-2011-5245", "CVE-2012-0818");
  script_bugtraq_id(51748, 51766);
  script_xref(name:"RHSA", value:"2012:0421");

  script_name(english:"RHEL 6 : rhevm (RHSA-2012:0421)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rhevm packages that fix one security issue and various bugs
are now available.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Red Hat Enterprise Virtualization Manager is a visual tool for
centrally managing collections of virtual machines running Red Hat
Enterprise Linux and Microsoft Windows. These packages also include
the Red Hat Enterprise Virtualization Manager REST (Representational
State Transfer) API, a set of scriptable commands that give
administrators the ability to perform queries and operations on Red
Hat Enterprise Virtualization Manager.

It was found that RESTEasy was vulnerable to XML External Entity (XXE)
attacks. If a remote attacker who is able to access the Red Hat
Enterprise Virtualization Manager REST API submitted a request
containing an external XML entity to a RESTEasy endpoint, the entity
would be resolved, allowing the attacker to read files accessible to
the user running the application server. This flaw affected DOM
(Document Object Model) Document and JAXB (Java Architecture for XML
Binding) input. (CVE-2012-0818)

This update also fixes the following bugs :

* Previously the REST API was ignoring the 'Accept' header. This made
it impossible to retrieve detailed information about specific
sub-collections, including hosts and disks. The REST API has been
updated and now processes the 'Accept' header as originally intended.
(BZ#771369)

* The 'start_time' Virtual Machine property was previously always set.
This meant that even Virtual Machines that were stopped, had a value
for 'start_time'. An update has been made to ensure that the
'start_time' property is only set when the Virtual Machine has been
started, and is running. (BZ#772975)

* The 'rhevm-setup' script previously only ran successfully on systems
with their locale set to 'en_US.UTF-8', 'en_US.utf-8', or
'en_US.utf8'. The script has since been updated to also run
successfully in additional locales, including 'ja_JP.UTF-8'.
(BZ#784860)

* The REST API did not previously validate that all required
parameters were provided when enabling power management. The response
code returned would also incorrectly indicate the operation had
succeeded where mandatory parameters were not supplied. An update has
been made to ensure that the power management parameters are validated
correctly. (BZ#785744)

* Previously no warning or error was issued when the amount of free
disk space on a host was low. When no free disk space remained on the
host it would become non-responsive with no prior warning. An update
has been made to report a warning in the audit log when a host's free
disk space is less than 1000 MB, and an error when a host's free disk
space is less than 500 MB. (BZ#786132)

* When importing Virtual Machines no notification was provided if the
MAC address of the network interface card clashed with that of an
existing Virtual Machine. Now when this occurs a message is printed to
the audit log, highlighting the need for manual intervention.
(BZ#795416)

* Previously it was not possible to set more, or less, than one value
for SpiceSecureChannels using the rhevm-config tool. This meant it was
not possible to encrypt all SPICE channels. The rhevm-config tool has
been updated and it is now possible to encrypt all SPICE channels, by
adding them to the SpiceSecureChannels configuration key. (BZ#784012)

All Red Hat Enterprise Virtualization users are advised to upgrade to
these updated packages, which address this vulnerability and fix these
bugs. Refer to the Solution section for information about installing
this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-5245.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0818.html"
  );
  # http://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Virtualization/3.0/html/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?44b2ccfe"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0421.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-dbscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-genericapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-iso-uploader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-jboss-deps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-log-collector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-notification-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-restapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-tools-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-userportal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhevm-webadmin-portal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0421";
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
  if (rpm_exists(rpm:"rhevm-3.0.", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rhevm-3.0.3_0001-3.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-backend-3.0.", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rhevm-backend-3.0.3_0001-3.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-config-3.0.", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rhevm-config-3.0.3_0001-3.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-dbscripts-3.0.", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rhevm-dbscripts-3.0.3_0001-3.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-debuginfo-3.0.", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rhevm-debuginfo-3.0.3_0001-3.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-genericapi-3.0.", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rhevm-genericapi-3.0.3_0001-3.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-iso-uploader-3.0.", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rhevm-iso-uploader-3.0.3_0001-3.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-jboss-deps-3.0.", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rhevm-jboss-deps-3.0.3_0001-3.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-log-collector-3.0.", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rhevm-log-collector-3.0.3_0001-3.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-notification-service-3.0.", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rhevm-notification-service-3.0.3_0001-3.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-restapi-3.0.", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rhevm-restapi-3.0.3_0001-3.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-setup-3.0.", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rhevm-setup-3.0.3_0001-3.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-tools-common-3.0.", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rhevm-tools-common-3.0.3_0001-3.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-userportal-3.0.", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rhevm-userportal-3.0.3_0001-3.el6")) flag++;
  if (rpm_exists(rpm:"rhevm-webadmin-portal-3.0.", release:"RHEL6") && rpm_check(release:"RHEL6", cpu:"x86_64", reference:"rhevm-webadmin-portal-3.0.3_0001-3.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rhevm / rhevm-backend / rhevm-config / rhevm-dbscripts / etc");
  }
}
