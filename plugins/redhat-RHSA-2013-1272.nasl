#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1272. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70011);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2013-4296", "CVE-2013-4311");
  script_bugtraq_id(62508, 62510);
  script_osvdb_id(97506, 97507);
  script_xref(name:"RHSA", value:"2013:1272");

  script_name(english:"RHEL 6 : libvirt (RHSA-2013:1272)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libvirt packages that fix two security issues and several bugs
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems. In
addition, libvirt provides tools for remote management of virtualized
systems.

libvirt invokes the PolicyKit pkcheck utility to handle authorization.
A race condition was found in the way libvirt used this utility,
allowing a local user to bypass intended PolicyKit authorizations or
execute arbitrary commands with root privileges. (CVE-2013-4311)

Note: With this update, libvirt has been rebuilt to communicate with
PolicyKit via a different API that is not vulnerable to the race
condition. The polkit RHSA-2013:1270 advisory must also be installed
to fix the CVE-2013-4311 issue.

An invalid free flaw was found in libvirtd's
remoteDispatchDomainMemoryStats function. An attacker able to
establish a read-only connection to libvirtd could use this flaw to
crash libvirtd. (CVE-2013-4296)

The CVE-2013-4296 issue was discovered by Daniel P. Berrange of Red
Hat.

This update also fixes the following bugs :

* Prior to this update, the libvirtd daemon leaked memory in the
virCgroupMoveTask() function. A fix has been provided which prevents
libvirtd from incorrect management of memory allocations. (BZ#984556)

* Previously, the libvirtd daemon was accessing one byte before the
array in the virCgroupGetValueStr() function. This bug has been fixed
and libvirtd now stays within the array bounds. (BZ#984561)

* When migrating, libvirtd leaked the migration URI (Uniform Resource
Identifier) on destination. A patch has been provided to fix this bug
and the migration URI is now freed correctly. (BZ#984578)

* Updating a network interface using virDomainUpdateDeviceFlags API
failed when a boot order was set for that interface. The update failed
even if the boot order was set in the provided device XML. The
virDomainUpdateDeviceFlags API has been fixed to correctly parse the
boot order specification from the provided device XML and updating
network interfaces with boot orders now works as expected.
(BZ#1003934)

Users of libvirt are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing the updated packages, libvirtd will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4296.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4311.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://rhn.redhat.com/errata/RHSA-2013-1270.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1272.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:1272";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libvirt-0.10.2-18.el6_4.14")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libvirt-0.10.2-18.el6_4.14")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libvirt-0.10.2-18.el6_4.14")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libvirt-client-0.10.2-18.el6_4.14")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libvirt-debuginfo-0.10.2-18.el6_4.14")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libvirt-devel-0.10.2-18.el6_4.14")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libvirt-lock-sanlock-0.10.2-18.el6_4.14")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libvirt-python-0.10.2-18.el6_4.14")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libvirt-python-0.10.2-18.el6_4.14")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libvirt-python-0.10.2-18.el6_4.14")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-client / libvirt-debuginfo / libvirt-devel / etc");
  }
}
