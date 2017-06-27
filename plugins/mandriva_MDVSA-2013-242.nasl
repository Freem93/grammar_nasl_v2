#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2013:242. 
# The text itself is copyright (C) Mandriva S.A.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(70162);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/11/25 11:41:41 $");

  script_cve_id("CVE-2013-2888", "CVE-2013-2889", "CVE-2013-2892", "CVE-2013-2893", "CVE-2013-2895", "CVE-2013-2896", "CVE-2013-2897", "CVE-2013-2899", "CVE-2013-4162", "CVE-2013-4163", "CVE-2013-4254");
  script_bugtraq_id(61411, 61412, 61793, 62042, 62043, 62044, 62045, 62046, 62048, 62049, 62050);
  script_xref(name:"MDVSA", value:"2013:242");

  script_name(english:"Mandriva Linux Security Advisory : kernel (MDVSA-2013:242)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been found and corrected in the Linux
kernel :

Multiple array index errors in drivers/hid/hid-core.c in the Human
Interface Device (HID) subsystem in the Linux kernel through 3.11
allow physically proximate attackers to execute arbitrary code or
cause a denial of service (heap memory corruption) via a crafted
device that provides an invalid Report ID (CVE-2013-2888).

drivers/hid/hid-zpff.c in the Human Interface Device (HID) subsystem
in the Linux kernel through 3.11, when CONFIG_HID_ZEROPLUS is enabled,
allows physically proximate attackers to cause a denial of service
(heap-based out-of-bounds write) via a crafted device (CVE-2013-2889).

drivers/hid/hid-pl.c in the Human Interface Device (HID) subsystem in
the Linux kernel through 3.11, when CONFIG_HID_PANTHERLORD is enabled,
allows physically proximate attackers to cause a denial of service
(heap-based out-of-bounds write) via a crafted device (CVE-2013-2892).

The Human Interface Device (HID) subsystem in the Linux kernel through
3.11, when CONFIG_LOGITECH_FF, CONFIG_LOGIG940_FF, or
CONFIG_LOGIWHEELS_FF is enabled, allows physically proximate attackers
to cause a denial of service (heap-based out-of-bounds write) via a
crafted device, related to (1) drivers/hid/hid-lgff.c, (2)
drivers/hid/hid-lg3ff.c, and (3) drivers/hid/hid-lg4ff.c
(CVE-2013-2893).

drivers/hid/hid-logitech-dj.c in the Human Interface Device (HID)
subsystem in the Linux kernel through 3.11, when
CONFIG_HID_LOGITECH_DJ is enabled, allows physically proximate
attackers to cause a denial of service (NULL pointer dereference and
OOPS) or obtain sensitive information from kernel memory via a crafted
device (CVE-2013-2895).

drivers/hid/hid-ntrig.c in the Human Interface Device (HID) subsystem
in the Linux kernel through 3.11, when CONFIG_HID_NTRIG is enabled,
allows physically proximate attackers to cause a denial of service
(NULL pointer dereference and OOPS) via a crafted device
(CVE-2013-2896).

Multiple array index errors in drivers/hid/hid-multitouch.c in the
Human Interface Device (HID) subsystem in the Linux kernel through
3.11, when CONFIG_HID_MULTITOUCH is enabled, allow physically
proximate attackers to cause a denial of service (heap memory
corruption, or NULL pointer dereference and OOPS) via a crafted device
(CVE-2013-2897).

drivers/hid/hid-picolcd_core.c in the Human Interface Device (HID)
subsystem in the Linux kernel through 3.11, when CONFIG_HID_PICOLCD is
enabled, allows physically proximate attackers to cause a denial of
service (NULL pointer dereference and OOPS) via a crafted device
(CVE-2013-2899).

The udp_v6_push_pending_frames function in net/ipv6/udp.c in the IPv6
implementation in the Linux kernel through 3.10.3 makes an incorrect
function call for pending data, which allows local users to cause a
denial of service (BUG and system crash) via a crafted application
that uses the UDP_CORK option in a setsockopt system call
(CVE-2013-4162).

The ip6_append_data_mtu function in net/ipv6/ip6_output.c in the IPv6
implementation in the Linux kernel through 3.10.3 does not properly
maintain information about whether the IPV6_MTU setsockopt option had
been specified, which allows local users to cause a denial of service
(BUG and system crash) via a crafted application that uses the
UDP_CORK option in a setsockopt system call (CVE-2013-4163).

The validate_event function in arch/arm/kernel/perf_event.c in the
Linux kernel before 3.10.8 on the ARM platform allows local users to
gain privileges or cause a denial of service (NULL pointer dereference
and system crash) by adding a hardware event to an event group led by
a software event (CVE-2013-4254

The updated packages provides a solution for these security issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:cpupower");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cpupower-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64cpupower0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"cpupower-3.4.62-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-firmware-3.4.62-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-headers-3.4.62-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-3.4.62-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"kernel-server-devel-3.4.62-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", reference:"kernel-source-3.4.62-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower-devel-3.4.62-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64cpupower0-3.4.62-1.1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"perf-3.4.62-1.1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
