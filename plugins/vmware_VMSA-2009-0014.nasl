#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2009-0014. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(42179);
  script_version("$Revision: 1.31 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id("CVE-2007-6063", "CVE-2008-0598", "CVE-2008-2086", "CVE-2008-2136", "CVE-2008-2812", "CVE-2008-3275", "CVE-2008-3525", "CVE-2008-4210", "CVE-2008-5339", "CVE-2008-5340", "CVE-2008-5341", "CVE-2008-5342", "CVE-2008-5343", "CVE-2008-5344", "CVE-2008-5345", "CVE-2008-5346", "CVE-2008-5347", "CVE-2008-5348", "CVE-2008-5349", "CVE-2008-5350", "CVE-2008-5351", "CVE-2008-5352", "CVE-2008-5353", "CVE-2008-5354", "CVE-2008-5355", "CVE-2008-5356", "CVE-2008-5357", "CVE-2008-5358", "CVE-2008-5359", "CVE-2008-5360", "CVE-2009-0692", "CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1099", "CVE-2009-1100", "CVE-2009-1101", "CVE-2009-1102", "CVE-2009-1103", "CVE-2009-1104", "CVE-2009-1105", "CVE-2009-1106", "CVE-2009-1107", "CVE-2009-1893");
  script_bugtraq_id(35668);
  script_osvdb_id(39240, 45421, 46918, 46920, 46921, 46922, 46923, 46924, 46925, 46926, 47788, 48432, 48781, 49081, 50495, 50496, 50497, 50498, 50499, 50500, 50501, 50502, 50503, 50504, 50505, 50506, 50507, 50508, 50509, 50510, 50511, 50512, 50513, 50514, 50515, 50516, 50517, 53164, 53165, 53166, 53167, 53168, 53169, 53170, 53171, 53172, 53173, 53174, 53175, 53176, 53177, 53178, 55819, 56464);
  script_xref(name:"VMSA", value:"2009-0014");

  script_name(english:"VMSA-2009-0014 : VMware ESX patches for DHCP, Service Console kernel, and JRE resolve multiple security issues");
  script_summary(english:"Checks esxupdate output for the patches");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote VMware ESX host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. Service Console update for DHCP and third-party library update
   for DHCP client.

   DHCP is an Internet-standard protocol by which a computer can be
   connected to a local network, ask to be given configuration
   information, and receive from a server enough information to
   configure itself as a member of that network.

   A stack-based buffer overflow in the script_write_params method in
   ISC DHCP dhclient allows remote DHCP servers to execute arbitrary
   code via a crafted subnet-mask option.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-0692 to this issue.

   An insecure temporary file use flaw was discovered in the DHCP
   daemon's init script ('/etc/init.d/dhcpd'). A local attacker could
   use this flaw to overwrite an arbitrary file with the output of the
   'dhcpd -t' command via a symbolic link attack, if a system
   administrator executed the DHCP init script with the 'configtest',
   'restart', or 'reload' option.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-1893 to this issue.

b. Updated Service Console package kernel

   Service Console package kernel update to version
   kernel-2.4.21-58.EL.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2008-4210, CVE-2008-3275, CVE-2008-0598,
   CVE-2008-2136, CVE-2008-2812, CVE-2007-6063, CVE-2008-3525 to the
   security issues fixed in kernel-2.4.21-58.EL

c. JRE Security Update

   JRE update to version 1.5.0_18, which addresses multiple security
   issues that existed in earlier releases of JRE.

   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the following names to the security issues fixed in
   JRE 1.5.0_17: CVE-2008-2086, CVE-2008-5347, CVE-2008-5348,
   CVE-2008-5349, CVE-2008-5350, CVE-2008-5351, CVE-2008-5352,
   CVE-2008-5353, CVE-2008-5354, CVE-2008-5356, CVE-2008-5357,
   CVE-2008-5358, CVE-2008-5359, CVE-2008-5360, CVE-2008-5339,
   CVE-2008-5342, CVE-2008-5344, CVE-2008-5345, CVE-2008-5346,
   CVE-2008-5340, CVE-2008-5341, CVE-2008-5343, and CVE-2008-5355.

   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the following names to the security issues fixed in
   JRE 1.5.0_18: CVE-2009-1093, CVE-2009-1094, CVE-2009-1095,
   CVE-2009-1096, CVE-2009-1097, CVE-2009-1098, CVE-2009-1099,
   CVE-2009-1100, CVE-2009-1101, CVE-2009-1102, CVE-2009-1103,
   CVE-2009-1104, CVE-2009-1105, CVE-2009-1106, and CVE-2009-1107."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2010/000076.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Calendar Deserialization Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(16, 20, 59, 94, 119, 189, 200, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/19");
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


init_esx_check(date:"2009-10-16");
flag = 0;


if (esx_check(ver:"ESX 3.0.3", patch:"ESX303-200910402-SG")) flag++;

if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200910401-SG",
    patch_updates : make_list("ESX350-200911201-UG", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200910403-SG",
    patch_updates : make_list("ESX350-201003403-SG", "ESX350-201203401-SG", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200910406-SG",
    patch_updates : make_list("ESX350-201203405-SG", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-200912404-SG",
    patch_updates : make_list("ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
