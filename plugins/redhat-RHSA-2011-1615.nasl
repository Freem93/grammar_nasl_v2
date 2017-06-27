#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1615. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64008);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/04 16:12:16 $");

  script_cve_id("CVE-2011-1773");
  script_bugtraq_id(50934);
  script_osvdb_id(77558);
  script_xref(name:"RHSA", value:"2011:1615");

  script_name(english:"RHEL 6 : virt-v2v (RHSA-2011:1615)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated virt-v2v package that fixes one security issue and several
bugs is now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

virt-v2v is a tool for converting and importing virtual machines to
libvirt-managed KVM (Kernel-based Virtual Machine), or Red Hat
Enterprise Virtualization.

Using virt-v2v to convert a guest that has a password-protected VNC
console to a KVM guest removed that password protection from the
converted guest: after conversion, a password was not required to
access the converted guest's VNC console. Now, converted guests will
require the same VNC console password as the original guest. Note that
when converting a guest to run on Red Hat Enterprise Virtualization,
virt-v2v will display a warning that VNC passwords are not supported.
(CVE-2011-1773)

Note: The Red Hat Enterprise Linux 6.2 perl-Sys-Virt update must also
be installed to correct CVE-2011-1773.

Bug fixes :

* When converting a guest virtual machine (VM), whose name contained
certain characters, virt-v2v would create a converted guest with a
corrupted name. Now, virt-v2v will not corrupt guest names.
(BZ#665883)

* There were numerous usability issues when running virt-v2v as a
non-root user. This update makes it simpler to run virt-v2v as a
non-root user. (BZ#671094)

* virt-v2v failed to convert a Microsoft Windows guest with Windows
Recovery Console installed in a separate partition. Now, virt-v2v will
successfully convert a guest with Windows Recovery Console installed
in a separate partition by ignoring that partition. (BZ#673066)

* virt-v2v failed to convert a Red Hat Enterprise Linux guest which
did not have the symlink '/boot/grub/menu.lst'. With this update,
virt-v2v can select a grub configuration file from several places.
(BZ#694364)

* This update removes information about the usage of deprecated
command line options in the virt-v2v man page. (BZ#694370)

* virt-v2v would fail to correctly change the allocation policy,
(sparse or preallocated) when converting a guest with QCOW2 image
format. The error message 'Cannot import VM, The selected disk
configuration is not supported' was displayed. With this update,
allocation policy changes to a guest with QCOW2 storage will work
correctly. (BZ#696089)

* The options '--network' and '--bridge' can not be used in
conjunction when converting a guest, but no error message was
displayed. With this update, virt-v2v will now display an error
message if the mutually exclusive '--network' and '--bridge' command
line options are both specified. (BZ#700759)

* virt-v2v failed to convert a multi-boot guest, and did not clean up
temporary storage and mount points after failure. With this update,
virt-v2v will prompt for which operating system to convert from a
multi-boot guest, and will correctly clean up if the process fails.
(BZ#702007)

* virt-v2v failed to correctly configure modprobe aliases when
converting a VMware ESX guest with VMware Tools installed. With this
update, modprobe aliases will be correctly configured. (BZ#707261)

* When converting a guest with preallocated raw storage using the
libvirtxml input method, virt-v2v failed with the erroneous error
message 'size(X) < usage(Y)'. This update removes this erroneous
error. (BZ#727489)

* When converting a Red Hat Enterprise Linux guest, virt-v2v did not
check that the Cirrus X driver was available before configuring it.
With this update, virt-v2v will attempt to install the Cirrus X driver
if it is required. (BZ#708961)

* VirtIO systems do not support the Windows Recovery Console on 32-bit
Windows XP. The virt-v2v man page has been updated to note this. On
Windows XP Professional x64 Edition, however, if Windows Recovery
Console is re-installed after conversion, it will work as expected.
(BZ#732421)

* Placing comments in the guest fstab file by means of the leading '#'
symbol caused an 'unknown filesystem' error after conversion of a
guest. With this update comments can now be used and error messages
will not be displayed. (BZ#677870)

Users of virt-v2v should upgrade to this updated package, which fixes
these issues and upgrades virt-v2v to version 0.8.3."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1773.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1615.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virt-v2v package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:virt-v2v");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/06");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:1615";
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
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"virt-v2v-0.8.3-5.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "virt-v2v");
  }
}
