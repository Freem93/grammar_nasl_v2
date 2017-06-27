#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2013-0002. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(64643);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/07/15 10:43:52 $");

  script_cve_id("CVE-2013-1406");
  script_bugtraq_id(57867);
  script_osvdb_id(90019);
  script_xref(name:"VMSA", value:"2013-0002");

  script_name(english:"VMSA-2013-0002 : VMware ESX, Workstation, Fusion, and View VMCI privilege escalation vulnerability");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESXi / ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. VMware VMCI privilege escalation

   VMware ESX, Workstation, Fusion, and View contain a 
   vulnerability in the handling of control code in vmci.sys.
   A local malicious user may exploit this vulnerability to 
   manipulate the memory allocation through the Virtual 
   Machine Communication Interface (VMCI) code. This could 
   result in a privilege escalation on Windows-based hosts and
   on Windows-based Guest Operating Systems.

   The vulnerability does not allow for privilege escalation
   from the Guest Operating System to the host (and vice versa).
   This means that host memory can not be manipulated from the
   Guest Operating System (and vice versa).

   Systems that have VMCI disabled are also affected by this issue.

   VMware would like to thank Derek Soeder of Cylance, Inc. and
   Kostya Kortchinsky of Microsoft for independently reporting this 
   issue to us. 

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2013-1406 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2013/000202.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/16");
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


init_esx_check(date:"2013-02-07");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201302401-SG",
    patch_updates : make_list("ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG")
  )
) flag++;

if (esx_check(ver:"ESXi 4.0", patch:"ESXi400-201302402-SG")) flag++;

if (esx_check(ver:"ESXi 5.0", vib:"VMware:tools-light:5.0.0-1.25.912577")) flag++;

if (esx_check(ver:"ESXi 5.1", vib:"VMware:tools-light:5.1.0-0.8.911593")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
