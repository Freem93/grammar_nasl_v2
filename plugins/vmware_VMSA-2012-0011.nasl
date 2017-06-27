#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2012-0011. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(59506);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2012-3288", "CVE-2012-3289");
  script_bugtraq_id(53996);
  script_osvdb_id(82979, 82980);
  script_xref(name:"VMSA", value:"2012-0011");
  script_xref(name:"IAVA", value:"2012-A-0099");
  script_xref(name:"IAVA", value:"2012-A-0100");

  script_name(english:"VMSA-2012-0011 : VMware hosted products and ESXi and ESX patches address security issues");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESXi / ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. VMware Host Checkpoint file memory corruption

   Input data is not properly validated when loading Checkpoint files.
   This may allow an attacker with the ability to load a specially
   crafted Checkpoint file to execute arbitrary code on the host.

   Workaround
   - None identified

   Mitigation
   - Do not import virtual machines from untrusted sources.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2012-3288 to this issue.

b. VMware Virtual Machine Remote Device Denial of Service

   A device (e.g. CD-ROM, keyboard) that is available to a virtual
   machine while physically connected to a system that does not run the
   virtual machine is referred to as a remote device.

   Traffic coming from remote virtual devices is incorrectly handled.
   This may allow an attacker who is capable of manipulating the
   traffic from a remote virtual device to crash the virtual machine.

   Workaround
   - None identified

   Mitigation
   - Users need administrative privileges on the virtual machine
     in order to attach remote devices.
   - Do not attach untrusted remote devices to a virtual machine.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2012-3289 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2012/000178.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/15");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  script_family(english:"VMware ESX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/VMware/release", "Host/VMware/version");
  script_require_ports("Host/VMware/esxupdate", "Host/VMware/esxcli_software_vibs");

  exit(0);
}


include("audit.inc");
include("vmware_esx_packages.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/VMware/release")) audit(AUDIT_OS_NOT, "VMware ESX / ESXi");
if (
  !get_kb_item("Host/VMware/esxcli_software_vibs") &&
  !get_kb_item("Host/VMware/esxupdate")
) audit(AUDIT_PACKAGE_LIST_MISSING);


init_esx_check(date:"2012-06-14");
flag = 0;


if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201206401-SG")) flag++;

if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201206401-SG",
    patch_updates : make_list("ESX400-201209401-SG", "ESX400-201302401-SG", "ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201206401-SG",
    patch_updates : make_list("ESX410-201208101-SG", "ESX410-201211401-SG", "ESX410-201301401-SG", "ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG", "ESX410-Update03")
  )
) flag++;

if (esx_check(ver:"ESXi 3.5.0", patch:"ESXe350-201206401-I-SG")) flag++;

if (
  esx_check(
    ver           : "ESXi 4.0",
    patch         : "ESXi400-201206401-SG",
    patch_updates : make_list("ESXi400-201209401-SG", "ESXi400-201302401-SG", "ESXi400-201305401-SG", "ESXi400-201310401-SG", "ESXi400-201404401-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.1",
    patch         : "ESXi410-201206401-SG",
    patch_updates : make_list("ESXi410-201208101-SG", "ESXi410-201211401-SG", "ESXi410-201301401-SG", "ESXi410-201304401-SG", "ESXi410-201307401-SG", "ESXi410-201312401-SG", "ESXi410-201404401-SG", "ESXi410-Update03")
  )
) flag++;

if (esx_check(ver:"ESXi 5.0", vib:"VMware:esx-base:5.0.0-1.16.721882")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
