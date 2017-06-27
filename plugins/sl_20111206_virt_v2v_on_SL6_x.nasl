#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61201);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/02/11 11:42:05 $");

  script_cve_id("CVE-2011-1773");

  script_name(english:"Scientific Linux Security Update : virt-v2v on SL6.x x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"virt-v2v is a tool for converting and importing virtual machines to
libvirt-managed KVM (Kernel-based Virtual Machine).

Using virt-v2v to convert a guest that has a password-protected VNC
console to a KVM guest removed that password protection from the
converted guest: after conversion, a password was not required to
access the converted guest's VNC console. Now, converted guests will
require the same VNC console password as the original guest. Note that
when converting a guest to run on RHEV, virt-v2v will display a
warning that VNC passwords are not supported. (CVE-2011-1773)

Bug fixes :

  - When converting a guest virtual machine (VM), whose name
    contained certain characters, virt-v2v would create a
    converted guest with a corrupted name. Now, virt-v2v
    will not corrupt guest names.

  - There were numerous usability issues when running
    virt-v2v as a non-root user. This update makes it
    simpler to run virt-v2v as a non-root user.

  - virt-v2v failed to convert a Microsoft Windows guest
    with Windows Recovery Console installed in a separate
    partition. Now, virt-v2v will successfully convert a
    guest with Windows Recovery Console installed in a
    separate partition by ignoring that partition.

  - virt-v2v failed to convert a Linux guest which did not
    have the symlink '/boot/grub/menu.lst'. With this
    update, virt-v2v can select a grub configuration file
    from several places.

  - This update removes information about the usage of
    deprecated command line options in the virt-v2v man
    page.

  - virt-v2v would fail to correctly change the allocation
    policy, (sparse or preallocated) when converting a guest
    with QCOW2 image format. The error message 'Cannot
    import VM, The selected disk configuration is not
    supported' was displayed. With this update, allocation
    policy changes to a guest with QCOW2 storage will work
    correctly.

  - The options '--network' and '--bridge' can not be used
    in conjunction when converting a guest, but no error
    message was displayed. With this update, virt-v2v will
    now display an error message if the mutually exclusive
    '--network' and '--bridge' command line options are both
    specified.

  - virt-v2v failed to convert a multi-boot guest, and did
    not clean up temporary storage and mount points after
    failure. With this update, virt-v2v will prompt for
    which operating system to convert from a multi-boot
    guest, and will correctly clean up if the process fails.

  - virt-v2v failed to correctly configure modprobe aliases
    when converting a VMware ESX guest with VMware Tools
    installed. With this update, modprobe aliases will be
    correctly configured.

  - When converting a guest with preallocated raw storage
    using the libvirtxml input method, virt-v2v failed with
    the erroneous error message 'size(X) < usage(Y)'. This
    update removes this erroneous error.

  - When converting a Linux guest, virt-v2v did not check
    that the Cirrus X driver was available before
    configuring it. With this update, virt-v2v will attempt
    to install the Cirrus X driver if it is required.

  - VirtIO systems do not support the Windows Recovery
    Console on 32-bit Windows XP. The virt-v2v man page has
    been updated to note this. On Windows XP Professional
    x64 Edition, however, if Windows Recovery Console is
    re-installed after conversion, it will work as expected.

  - Placing comments in the guest fstab file by means of the
    leading '#' symbol caused an 'unknown filesystem' error
    after conversion of a guest. With this update comments
    can now be used and error messages will not be
    displayed.

Users of virt-v2v should upgrade to this updated package, which fixes
these issues and upgrades virt-v2v to version 0.8.3."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1112&L=scientific-linux-errata&T=0&P=3654
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8892143a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected virt-v2v package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"virt-v2v-0.8.3-5.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
