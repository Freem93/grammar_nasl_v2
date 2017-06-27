#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:115. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82368);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/30 13:59:00 $");

  script_cve_id("CVE-2013-6456", "CVE-2014-0179", "CVE-2014-3633", "CVE-2014-3657", "CVE-2014-7823", "CVE-2014-8136", "CVE-2015-0236");
  script_xref(name:"MDVSA", value:"2015:115");

  script_name(english:"Mandriva Linux Security Advisory : libvirt (MDVSA-2015:115)");
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
"Updated libvirt packages fix security vulnerabilities :

The LXC driver (lxc/lxc_driver.c) in libvirt 1.0.1 through 1.2.1
allows local users to (1) delete arbitrary host devices via the
virDomainDeviceDettach API and a symlink attack on /dev in the
container; (2) create arbitrary nodes (mknod) via the
virDomainDeviceAttach API and a symlink attack on /dev in the
container; and cause a denial of service (shutdown or reboot host OS)
via the (3) virDomainShutdown or (4) virDomainReboot API and a symlink
attack on /dev/initctl in the container, related to paths under
/proc//root and the virInitctlSetRunLevel function (CVE-2013-6456).

libvirt was patched to prevent expansion of entities when parsing XML
files. This vulnerability allowed malicious users to read arbitrary
files or cause a denial of service (CVE-2014-0179).

An out-of-bounds read flaw was found in the way libvirt's
qemuDomainGetBlockIoTune() function looked up the disk index in a
non-persistent (live) disk configuration while a persistent disk
configuration was being indexed. A remote attacker able to establish a
read-only connection to libvirtd could use this flaw to crash libvirtd
or, potentially, leak memory from the libvirtd process
(CVE-2014-3633).

A denial of service flaw was found in the way libvirt's
virConnectListAllDomains() function computed the number of used
domains. A remote attacker able to establish a read-only connection to
libvirtd could use this flaw to make any domain operations within
libvirt unresponsive (CVE-2014-3657).

Eric Blake discovered that libvirt incorrectly handled permissions
when processing the qemuDomainFormatXML command. An attacker with
read-only privileges could possibly use this to gain access to certain
information from the domain xml file (CVE-2014-7823).

The qemuDomainMigratePerform and qemuDomainMigrateFinish2 functions in
qemu/qemu_driver.c in libvirt do not unlock the domain when an ACL
check fails, which allow local users to cause a denial of service via
unspecified vectors (CVE-2014-8136).

The XML getters for for save images and snapshots objects don't check
ACLs for the VIR_DOMAIN_XML_SECURE flag and might possibly dump
security sensitive information. A remote attacker able to establish a
connection to libvirtd could use this flaw to cause leak certain
limited information from the domain xml file (CVE-2015-0236)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0243.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0401.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2014-0470.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://advisories.mageia.org/MGASA-2015-0046.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected lib64virt-devel, lib64virt0 and / or libvirt-utils
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:N/I:P/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64virt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64virt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libvirt-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64virt-devel-1.2.1-2.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64virt0-1.2.1-2.1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"libvirt-utils-1.2.1-2.1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
