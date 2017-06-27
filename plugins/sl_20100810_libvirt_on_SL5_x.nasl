#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60835);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/10/03 00:00:32 $");

  script_cve_id("CVE-2010-2239", "CVE-2010-2242");

  script_name(english:"Scientific Linux Security Update : libvirt on SL5.x i386/x86_64");
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
"It was found that libvirt did not set the user-defined backing store
format when creating a new image, possibly resulting in applications
having to probe the backing store to discover the format. A privileged
guest user could use this flaw to read arbitrary files on the host.
(CVE-2010-2239)

It was found that libvirt created insecure iptables rules on the host
when a guest system was configured for IP masquerading, allowing the
guest to use privileged ports on the host when accessing network
resources. A privileged guest user could use this flaw to access
network resources that would otherwise not be accessible to the guest.
(CVE-2010-2242)

This update also fixes the following bugs :

  - a Linux software bridge assumes the MAC address of the
    enslaved interface with the numerically lowest MAC
    address. When the bridge changes its MAC address, for a
    period of time it does not relay packets across network
    segments, resulting in a temporary network 'blackout'.
    The bridge should thus avoid changing its MAC address in
    order not to disrupt network communications.

The Linux kernel assigns network TAP devices a random MAC address.
Occasionally, this random MAC address is lower than that of the
physical interface which is enslaved (for example, eth0 or eth1),
which causes the bridge to change its MAC address, thereby disrupting
network communications for a period of time.

With this update, libvirt now sets an explicit MAC address for all TAP
devices created using the configured MAC address from the XML, but
with the high bit set to 0xFE. The result is that TAP device MAC
addresses are now numerically greater than those for physical
interfaces, and bridges should no longer attempt to switch their MAC
address to that of the TAP device, thus avoiding potential spurious
network disruptions. (BZ#617243)

  - a memory leak in the libvirt driver for the Xen
    hypervisor has been fixed with this update. (BZ#619711)

  - the xm and virsh management user interfaces for virtual
    guests can be called on the command line to list the
    number of active guests. However, under certain
    circumstances, running the 'virsh list' command resulted
    in virsh not listing all of the virtual guests that were
    active (that is, running) at the time. This update
    incorporates a fix that matches the logic used for
    determining active guests with that of 'xm list', such
    that both commands should now list the same number of
    active virtual guests under all circumstances.
    (BZ#618200)

After installing the updated packages, the system must be rebooted for
the update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1008&L=scientific-linux-errata&T=0&P=1435
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?59a7d1a6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=617243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=618200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=619711"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libvirt, libvirt-devel and / or libvirt-python
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
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
if (rpm_check(release:"SL5", reference:"libvirt-0.6.3-33.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"libvirt-devel-0.6.3-33.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"libvirt-python-0.6.3-33.el5_5.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
