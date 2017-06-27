#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2013-0014. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(71214);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/07/15 10:43:53 $");

  script_cve_id("CVE-2013-3519");
  script_bugtraq_id(64075);
  script_osvdb_id(100514);
  script_xref(name:"VMSA", value:"2013-0014");

  script_name(english:"VMSA-2013-0014 : VMware Workstation, Fusion, ESXi and ESX patches address a guest privilege escalation");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESXi / ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. VMware LGTOSYNC privilege escalation.

   VMware ESX, Workstation and Fusion contain a vulnerability 
   in the handling of control code in lgtosync.sys. A local 
   malicious user may exploit this vulnerability to manipulate the 
   memory allocation. This could result in a privilege 
   escalation on 32-bit Guest Operating Systems running Windows 2000
   Server, Windows XP or Windows 2003 Server on ESXi and ESX; or 
   Windows XP on Workstation and Fusion.

   The vulnerability does not allow for privilege escalation
   from the Guest Operating System to the host. This means 
   that host memory can not be manipulated from the Guest 
   Operating System.

   VMware would like to thank Derek Soeder of Cylance, Inc. for 
   reporting this issue to us. 

   The Common Vulnerabilityies and Exposures project (cve.mitre.org)
   has assigned the name CVE-2013-3519 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2013/000226.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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


init_esx_check(date:"2013-12-03");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201305401-SG",
    patch_updates : make_list("ESX400-201310401-SG", "ESX400-201404401-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201301401-SG",
    patch_updates : make_list("ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.0",
    patch         : "ESXi400-201305401-SG",
    patch_updates : make_list("ESXi400-201310401-SG", "ESXi400-201404401-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.1",
    patch         : "ESXi410-201301401-SG",
    patch_updates : make_list("ESXi410-201304401-SG", "ESXi410-201307401-SG", "ESXi410-201312401-SG", "ESXi410-201404401-SG")
  )
) flag++;

if (esx_check(ver:"ESXi 5.0", vib:"VMware:tools-light:5.0.0-2.29.1022489")) flag++;

if (esx_check(ver:"ESXi 5.1", vib:"VMware:tools-light:5.1.0-0.11.1063671")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
