#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-5308.
#

include("compat.inc");

if (description)
{
  script_id(33182);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 22:23:16 $");

  script_cve_id("CVE-2008-1673");
  script_bugtraq_id(29589);
  script_xref(name:"FEDORA", value:"2008-5308");

  script_name(english:"Fedora 9 : kernel-2.6.25.6-55.fc9 (2008-5308)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to kernel 2.6.25.6:
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.25.5
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.25.6
CVE-2008-1673: The asn1 implementation in (a) the Linux kernel 2.4
before 2.4.36.6 and 2.6 before 2.6.25.5, as used in the cifs and
ip_nat_snmp_basic modules; and (b) the gxsnmp package; does not
properly validate length values during decoding of ASN.1 BER data,
which allows remote attackers to cause a denial of service (crash) or
execute arbitrary code via (1) a length greater than the working
buffer, which can lead to an unspecified overflow; (2) an oid length
of zero, which can lead to an off-by-one error; or (3) an indefinite
length for a primitive encoding. Bugs fixed: 447518 - Call to capget()
overflows buffers 448056 - applesmc filling log file 450191 - DMA mode
disabled for DVD drive, reverts to PIO4 439197 - thinkpad x61t crash
when undocking 445761 - MacBook4,1 keyboard and trackpad do not work
properly 447812 - Netlink messages from 'tc' to sch_netem module are
not interpreted correctly 449817 - SD card reader causes kernel panic
during startup if card inserted 242208 - Freeze On Boot w/ Audigy
PCMCIA 443552 - Kernel 2.6.25 + Wine = hang Additional bugs fixed:
F8#224005 - pata_pcmcia fails F8#450499 - kernel-2.6.25.4-10.fc8
breaks setkey -m tunnel options in ipsec F8#445553 - DMAR
(intel_iommu) broken on yet another machine Additional updates/fixes:
- Upstream wireless updates from 2008-05-22
(http://marc.info/?l=linux-wireless&m=121146112404515&w=2) - Upstream
wireless fixes from 2008-05-28 (http://marc.info/?l=linux-
wireless&m=121201250110162&w=2) - Fix oops in lirc_i2c module - Add
lirc support for additional MCE receivers - Upstream wireless fixes
from 2008-06-03
(http://marc.info/?l=linux-wireless&m=121252137324941&w=2) - Add
kernel 3D support for ATI Radeon R500 (X1300-X1950)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=linux-"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=linux-wireless&m=121146112404515&w=2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=linux-wireless&m=121252137324941&w=2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.25.5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.25.6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=242208"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=439197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=443552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=445761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=447518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=447812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=448056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=449817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=450191"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-June/011330.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16fa2d19"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC9", reference:"kernel-2.6.25.6-55.fc9")) flag++;


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
