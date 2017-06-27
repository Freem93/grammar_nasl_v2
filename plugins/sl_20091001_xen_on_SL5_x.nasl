#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60674);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:54 $");

  script_cve_id("CVE-2009-3525");

  script_name(english:"Scientific Linux Security Update : xen on SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2009-3525 Xen: PyGrub missing support for password configuration
command

The pyGrub boot loader did not honor the 'password' option in the
grub.conf file for para-virtualized guests. Users with access to a
guest's console could use this flaw to bypass intended access
restrictions and boot the guest with arbitrary kernel boot options,
allowing them to get root privileges in the guest's operating system.
With this update, pyGrub correctly honors the 'password' option in
grub.conf for para-virtualized guests. (CVE-2009-3525)

This update also fixes the following bugs :

  - rebooting para-virtualized guests sometimes caused those
    guests to crash due to a race condition in the xend node
    control daemon. This update fixes this race condition so
    that rebooting guests no longer potentially causes them
    to crash and fail to reboot. (BZ#525141)

  - due to a race condition in the xend daemon, a guest
    could disappear from the list of running guests
    following a reboot, even though the guest rebooted
    successfully and was running. This update fixes this
    race condition so that guests always reappear in the
    guest list following a reboot. (BZ#525143)

  - attempting to use PCI pass-through to para-virtualized
    guests on certain kernels failed with a 'Function not
    implemented' error message. As a result, users requiring
    PCI pass-through on para-virtualized guests were not
    able to update the xen packages without also updating
    the kernel and thus requiring a reboot. These updated
    packages enable PCI pass-through for para-virtualized
    guests so that users do not need to upgrade the kernel
    in order to take advantage of PCI pass-through
    functionality. (BZ#525149)

After installing the updatedpackages, the xend service must be
restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0910&L=scientific-linux-errata&T=0&P=810
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd440dff"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=525141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=525143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=525149"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen, xen-devel and / or xen-libs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"xen-3.0.3-94.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"xen-devel-3.0.3-94.el5_4.1")) flag++;
if (rpm_check(release:"SL5", reference:"xen-libs-3.0.3-94.el5_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
