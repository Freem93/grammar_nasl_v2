#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0473. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79274);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/04 15:51:47 $");

  script_cve_id("CVE-2010-2223");
  script_osvdb_id(65796);
  script_xref(name:"RHSA", value:"2010:0473");

  script_name(english:"RHEL 5 : vdsm (RHSA-2010:0473)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated vdsm packages that fix one security issue, various bugs, and
add two enhancements are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The Virtual Desktop Server Manager (VDSM) is a management module that
serves as a Red Hat Enterprise Virtualization Manager (RHEV-M) agent
on Red Hat Enterprise Virtualization Hypervisor (RHEV-H) or Red Hat
Enterprise Linux hosts. VDSM allows RHEV-M to manage virtual machines
and storage pools, and retrieve statistics from both hosts and guests.

A flaw was found in the way VDSM handled the removal of a virtual
machine's (VM) data back end (such as an image or a volume). When
removing an image or a volume, it was not securely deleted from its
corresponding data domain as expected. A guest user in a new, raw VM,
created in a data domain that has had VMs deleted from it, could use
this flaw to read limited data from those deleted VMs, potentially
disclosing sensitive information. (CVE-2010-2223)

These updated vdsm packages also fix the following bugs :

* Kernel Samepage Merging (KSM) did not use all the available memory
(due to the memory not being zero-filled) if the memory did not belong
to the Linux guest. Thus, KSM was not effective in distributing the
memory to the Linux guests with the result of shared memory being
unavailable for Linux guests. With this update, KSM allows multiple
Linux guests to share the memory. (BZ#527405)

* the vds_bootstrap script failed when the host's temporary directory
was located on a different partition, with the following error :

[Errno 18] Invalid cross-device link using os.rename

With this update, vds_bootstrap no longer fails. (BZ#530322)

* vds_bootstrap failed to add a host to RHEV-M when the 'cpuspeed' and
the 'libvirt' services were not found. With this update, the host is
added to RHEV-M even when the aforementioned services are not present
in the system. (BZ#538751)

* previously, vds_bootstrap attempted to parse blank lines present in
network scripts (for example,
/etc/sysconfig/network-scripts/ifcfg-eth0). As a consequence, if a
network script contained blank lines, vds_bootstrap failed and an
error such as follows was written to /var/vdsm/vdsm.log (the error
example below is consequent to the blank line being present in
ifcfg-eth0) :

getBridgeParams: failed to read params of file
/etc/sysconfig/network-scripts/ifcfg-eth0 Error:list index out of
range

With this update, vds_bootstrap filters blank lines in network
configuration files, ensuring it does not fail if they are present.
(BZ#540479)

* the 'pool connect' utility did not save the master domain's
information to the disk. If VDSM was restarted, auto-reconnect
searched for a master domain with the highest version. If the master
domain was not available at that time, an incorrect domain was chosen
as the master. With this update, the correct domain is chosen as the
master. (BZ#543432)

* when using the RHEV-M interface to manage high-availability VMs,
power down requests were not honored. Consequently, some
high-availability virtual machines automatically rebooted instead of
shutting down after they received a command to shut down.
High-availability VMs now correctly process requests to shut down,
with the result that no VMs incorrectly reboot instead. (BZ#547112)

* after a host installation, the 'multipathd' service would restart
when the host was started from a multipath device. With this update,
the 'multipathd' service no longer restarts. (BZ#547305)

These updated vdsm packages also add the following enhancements :

* previously, import/export of VMs was not supported. With this update
import/export have been implemented. (BZ#482608)

* previously, the ISO image domain could not be shared with multiple
Data Centers. The user had to define an independent ISO domain for
each Data Center. With this update, the ISO image domain can be shared
between multiple Data Centers. (BZ#496448)

All vdsm users should upgrade to these updated packages, which resolve
these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-2223.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0473.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected vdsm22 and / or vdsm22-cli packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm22-cli");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/22");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0473";
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
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"vdsm22-4.5-62.el5rhev")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"vdsm22-cli-4.5-62.el5rhev")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vdsm22 / vdsm22-cli");
  }
}
