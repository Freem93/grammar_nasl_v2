#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0615 and 
# CentOS Errata and Security Advisory 2010:0615 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(48302);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/06/28 23:54:23 $");

  script_cve_id("CVE-2010-2239", "CVE-2010-2242");
  script_bugtraq_id(41981);
  script_osvdb_id(67299, 67300);
  script_xref(name:"RHSA", value:"2010:0615");

  script_name(english:"CentOS 5 : libvirt (CESA-2010:0615)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libvirt packages that fix two security issues and three bugs
are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems. In
addition, libvirt provides tools for remotely managing virtualized
systems.

It was found that libvirt did not set the user-defined backing store
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

Red Hat would like to thank Jeremy Nickurak for reporting the
CVE-2010-2242 issue.

This update also fixes the following bugs :

* a Linux software bridge assumes the MAC address of the enslaved
interface with the numerically lowest MAC address. When the bridge
changes its MAC address, for a period of time it does not relay
packets across network segments, resulting in a temporary network
'blackout'. The bridge should thus avoid changing its MAC address in
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

* a memory leak in the libvirt driver for the Xen hypervisor has been
fixed with this update. (BZ#619711)

* the xm and virsh management user interfaces for virtual guests can
be called on the command line to list the number of active guests.
However, under certain circumstances, running the 'virsh list' command
resulted in virsh not listing all of the virtual guests that were
active (that is, running) at the time. This update incorporates a fix
that matches the logic used for determining active guests with that of
'xm list', such that both commands should now list the same number of
active virtual guests under all circumstances. (BZ#618200)

All users of libvirt are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing the updated packages, the system must be rebooted for the
update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-August/016896.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?350e147f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-August/016897.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34150eae"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvirt packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvirt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"libvirt-0.6.3-33.el5_5.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libvirt-devel-0.6.3-33.el5_5.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libvirt-python-0.6.3-33.el5_5.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
