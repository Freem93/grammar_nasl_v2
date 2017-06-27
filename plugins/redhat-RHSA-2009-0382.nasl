#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0382. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63878);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/03 17:27:01 $");

  script_cve_id("CVE-2008-5086", "CVE-2009-0036");
  script_bugtraq_id(32905);
  script_xref(name:"RHSA", value:"2009:0382");

  script_name(english:"RHEL 5 : libvirt (RHSA-2009:0382)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libvirt packages that fix two security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

[Updated 5th May 2011] After installing this update and restarting the
libvirtd service, the 'virsh attach-disk' command failed. Rebooting
guest systems after installing the update resolved the issue. The
erratum text has been updated to reflect that guest systems must be
rebooted. Future updates will advise if a guest reboot is needed. No
changes have been made to the packages.

libvirt is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems.
libvirt also provides tools for remotely managing virtualized systems.

The libvirtd daemon was discovered to not properly check user
connection permissions before performing certain privileged actions,
such as requesting migration of an unprivileged guest domain to
another system. A local user able to establish a read-only connection
to libvirtd could use this flaw to perform actions that should be
restricted to read-write connections. (CVE-2008-5086)

libvirt_proxy, a setuid helper application allowing non-privileged
users to communicate with the hypervisor, was discovered to not
properly validate user requests. Local users could use this flaw to
cause a stack-based buffer overflow in libvirt_proxy, possibly
allowing them to run arbitrary code with root privileges.
(CVE-2009-0036)

All users are advised to upgrade to these updated packages, which
contain backported patches which resolve these issues. After
installing the update, libvirtd must be restarted manually (for
example, by issuing a 'service libvirtd restart' command), and guest
systems rebooted, for this change to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-5086.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0036.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2009-0382.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libvirt, libvirt-devel and / or libvirt-python
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2009:0382";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libvirt-0.3.3-14.el5_3.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libvirt-0.3.3-14.el5_3.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libvirt-devel-0.3.3-14.el5_3.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libvirt-devel-0.3.3-14.el5_3.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libvirt-python-0.3.3-14.el5_3.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libvirt-python-0.3.3-14.el5_3.1")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-devel / libvirt-python");
  }
}
