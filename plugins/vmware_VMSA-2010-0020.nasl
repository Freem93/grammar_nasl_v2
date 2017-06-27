#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2010-0020. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(99166);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/03 14:49:09 $");

  script_cve_id("CVE-2010-4573");
  script_bugtraq_id(45543);
  script_osvdb_id(70114);
  script_xref(name:"VMSA", value:"2010-0020");

  script_name(english:"VMSA-2010-0020 : VMware ESXi 4.1 Update Installer SFCB Authentication Flaw");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESXi host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. ESXi 4.1 Update Installer SFCB Authentication Flaw

   Under certain conditions, the ESXi 4.1 installer that upgrades an
   ESXi 3.5 or ESXi 4.0 host to ESXi 4.1 incorrectly handles the SFCB
   authentication mode. The result is that SFCB authentication could
   allow login with any username and password combination.

   An ESXi 4.1 host is affected if all of the following apply :
   - ESXi 4.1 was upgraded from ESXi 3.5 or ESXi 4.0.
   - The SFCB configuration file /etc/sfcb/sfcb.cfg was modified prior
     to the upgrade.
   - The sfcbd daemon is running (sfcbd runs by default).

   Workaround
   A workaround that can be applied to ESXi 4.1 is described in VMware
   Knowledge Base Article KB 1031761

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2010-4573 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2011/000496.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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


init_esx_check(date:"2010-12-21");
flag = 0;


if (
  esx_check(
    ver           : "ESXi 4.1",
    patch         : "ESXi410-201101201-SG",
    patch_updates : make_list("ESXi410-201104401-SG", "ESXi410-201110201-SG", "ESXi410-201201401-SG", "ESXi410-201204401-SG", "ESXi410-201205401-SG", "ESXi410-201206401-SG", "ESXi410-201208101-SG", "ESXi410-201211401-SG", "ESXi410-201301401-SG", "ESXi410-201304401-SG", "ESXi410-201307401-SG", "ESXi410-201312401-SG", "ESXi410-201404401-SG", "ESXi410-Update01", "ESXi410-Update02", "ESXi410-Update03")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
