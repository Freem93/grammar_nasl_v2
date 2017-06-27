#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2008-0018. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(40385);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id("CVE-2008-4281", "CVE-2008-4915");
  script_bugtraq_id(32168, 32172);
  script_osvdb_id(49795, 49947);
  script_xref(name:"VMSA", value:"2008-0018");

  script_name(english:"VMSA-2008-0018 : VMware Hosted products and patches for ESX and ESXi resolve two security issues");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESXi / ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. A privilege escalation on 32-bit and 64-bit guest operating systems

   VMware products emulate hardware functions and create the
   possibility to run guest operating systems.

   A flaw in the CPU hardware emulation might allow the virtual CPU to
   incorrectly handle the Trap flag. Exploitation of this flaw might
   lead to a privilege escalation on guest operating systems.  An
   attacker needs a user account on the guest operating system and
   have the ability to run applications.

   VMware would like to thank Derek Soeder for discovering
   this issue and working with us on its remediation.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2008-4915 to this issue.

b.  Directory traversal vulnerability

   VirtualCenter allows administrators to have fine-grained privileges.
   A directory traversal vulnerability might allow administrators to
   increase these privileges. In order to leverage this flaw, the
   administrator would need to have the Datastore.FileManagement
   privilege.

   VMware would like to thank Michel Toussaint for reporting this issue
   to us.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2008-4281 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2008/000042.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.5.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:3.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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


init_esx_check(date:"2008-11-06");
flag = 0;


if (esx_check(ver:"ESX 2.5.4", patch:"21")) flag++;

if (esx_check(ver:"ESX 2.5.5", patch:"10")) flag++;

if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1006680")) flag++;

if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200810201-UG",
    patch_updates : make_list("ESX350-200911201-UG", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;

if (esx_check(ver:"ESXi 3.5.0", patch:"ESXe350-200810401-O-UG")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
