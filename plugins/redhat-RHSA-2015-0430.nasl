#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0430. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81636);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/06 15:51:01 $");

  script_cve_id("CVE-2014-0189");
  script_xref(name:"RHSA", value:"2015:0430");

  script_name(english:"RHEL 7 : virt-who (RHSA-2015:0430)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated virt-who package that fixes one security issue, several
bugs, and adds various enhancements is now available for Red Hat
Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The virt-who package provides an agent that collects information about
virtual guests present in the system and reports them to the
subscription manager.

It was discovered that the /etc/sysconfig/virt-who configuration file,
which may contain hypervisor authentication credentials, was
world-readable. A local user could use this flaw to obtain
authentication credentials from this file. (CVE-2014-0189)

Red Hat would like to thank Sal Castiglione for reporting this issue.

The virt-who package has been upgraded to upstream version 0.11, which
provides a number of bug fixes and enhancements over the previous
version. The most notable bug fixes and enhancements include :

* Support for remote libvirt. * A fix for using encrypted passwords. *
Bug fixes and enhancements that increase the stability of virt-who.
(BZ#1122489)

This update also fixes the following bugs :

* Prior to this update, the virt-who agent failed to read the list of
virtual guests provided by the VDSM daemon. As a consequence, when in
VDSM mode, the virt-who agent was not able to send updates about
virtual guests to Subscription Asset Manager (SAM) and Red Hat
Satellite. With this update, the agent reads the list of guests when
in VDSM mode correctly and reports to SAM and Satellite as expected.
(BZ#1153405)

* Previously, virt-who used incorrect information when connecting to
Red Hat Satellite 5. Consequently, virt-who could not connect to Red
Hat Satellite 5 servers. The incorrect parameter has been corrected,
and virt-who can now successfully connect to Red Hat Satellite 5.
(BZ#1158859)

* Prior to this update, virt-who did not decode the hexadecimal
representation of a password before decrypting it. As a consequence,
the decrypted password did not match the original password, and
attempts to connect using the password failed. virt-who has been
updated to decode the encrypted password and, as a result, virt-who
now handles storing credentials using encrypted passwords as expected.
(BZ#1161607)

In addition, this update adds the following enhancement :

* With this update, virt-who is able to read the list of guests from a
remote libvirt hypervisor. (BZ#1127965)

Users of virt-who are advised to upgrade to this updated package,
which corrects these issues and adds these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0189.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-0430.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virt-who package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:virt-who");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/05");
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
  rhsa = "RHSA-2015:0430";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL7", reference:"virt-who-0.11-5.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "virt-who");
  }
}
