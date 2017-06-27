#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-8929.
#

include("compat.inc");

if (description)
{
  script_id(34480);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/08 20:21:54 $");

  script_cve_id("CVE-2008-3525", "CVE-2008-3831", "CVE-2008-4410", "CVE-2008-4554", "CVE-2008-4576");
  script_bugtraq_id(31565, 31634, 31792);
  script_xref(name:"FEDORA", value:"2008-8929");

  script_name(english:"Fedora 9 : kernel-2.6.26.6-79.fc9 (2008-8929)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update kernel from version 2.6.26.5 to 2.6.26.6:
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.26.6
CVE-2008-3831 An IOCTL in the i915 driver was not properly restricted
to users with the proper capabilities to use it. CVE-2008-4410 The
vmi_write_ldt_entry function in arch/x86/kernel/vmi_32.c in the
Virtual Machine Interface (VMI) in the Linux kernel 2.6.26.5 invokes
write_idt_entry where write_ldt_entry was intended, which allows local
users to cause a denial of service (persistent application failure)
via crafted function calls, related to the Java Runtime Environment
(JRE) experiencing improper LDT selector state, a different
vulnerability than CVE-2008-3247. CVE-2008-3525 The sbni_ioctl
function in drivers/net/wan/sbni.c in the wan subsystem in the Linux
kernel 2.6.26.3 does not check for the CAP_NET_ADMIN capability before
processing a (1) SIOCDEVRESINSTATS, (2) SIOCDEVSHWSTATE, (3)
SIOCDEVENSLAVE, or (4) SIOCDEVEMANSIPATE ioctl request, which allows
local users to bypass intended capability restrictions. CVE-2008-4554
The do_splice_from function in fs/splice.c in the Linux kernel before
2.6.27 does not reject file descriptors that have the O_APPEND flag
set, which allows local users to bypass append mode and make arbitrary
changes to other locations in the file. CVE-2008-4576 sctp in Linux
kernel before 2.6.25.18 allows remote attackers to cause a denial of
service (OOPS) via an INIT-ACK that states the peer does not support
AUTH, which causes the sctp_process_init function to clean up active
transports and triggers the OOPS when the T1-Init timer expires.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.26.6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=438606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=460550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=462156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=462178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=462919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=463034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=464613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=465873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=466303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=466511"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-October/015633.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c2a6ea6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"kernel-2.6.26.6-79.fc9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
