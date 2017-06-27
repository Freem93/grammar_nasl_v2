#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2013-0012. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(70527);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2013-5970", "CVE-2013-5971");
  script_bugtraq_id(63216, 63218);
  script_osvdb_id(94335, 94336, 94337, 94338, 94339, 94340, 94341, 94342, 94343, 94344, 94345, 94346, 94347, 94348, 94349, 94350, 94351, 94352, 94353, 94354, 94355, 94356, 94357, 94358, 94359, 94360, 94361, 94362, 94363, 94364, 94365, 94366, 94367, 94368, 94369, 94370, 94371, 94372, 94373, 94374);
  script_xref(name:"VMSA", value:"2013-0012");
  script_xref(name:"IAVA", value:"2013-A-0204");
  script_xref(name:"IAVA", value:"2013-A-0205");
  script_xref(name:"IAVA", value:"2013-A-0218");

  script_name(english:"VMSA-2013-0012 : VMware vSphere updates address multiple vulnerabilities");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESXi / ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. VMware ESXi and ESX contain a vulnerability in hostd-vmdb. 

   To exploit this vulnerability, an attacker must intercept and 
   modify the management traffic. Exploitation of the issue may lead
   to a Denial of Service of the hostd-vmdb service.

   To reduce the likelihood of exploitation, vSphere components 
   should be deployed on an isolated management network.
   
   VMware would like to thank Alex Chapman of Context Information 
   Security for reporting this issue to us. 

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2013-5970 to this issue.

b. VMware vSphere Web Client Server Session Fixation Vulnerability
   
   The VMware vSphere Web Client Server contains a vulnerability in
   the handling of session IDs. To exploit this vulnerability, an 
   attacker must know a valid session ID of an authenticated user. 
   Exploitation of the issue may lead to Elevation of Privilege.

   To reduce the likelihood of exploitation, vSphere components 
   should be deployed on an isolated management network.

   VMware would like to thank Alexey Tyurin of DSecRG for reporting
   this issue to us.

   The Common Vulnerabilities and Exposures project (cve.mitre.org) 
   has assigned the name CVE-2013-5971 to this issue.

c. vCenter and Update Manager, Oracle JRE update 1.6.0_51.
   
   Oracle JRE is updated to version 1.6.0_51, which addresses
   multiple security issues that existed in earlier releases of
   Oracle JRE. 

   Oracle has documented the CVE identifiers that are addressed
   in JRE 1.6.0_51 in the Oracle Java SE Critical Patch Update
   Advisory of June 2013. The References section provides a
   link to this advisory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2014/000232.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet ProviderSkeleton Insecure Invoke Method');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/20");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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


init_esx_check(date:"2013-10-17");
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
    patch         : "ESX410-201307401-SG",
    patch_updates : make_list("ESX410-201312401-SG", "ESX410-201404401-SG")
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
    patch         : "ESXi410-201307401-SG",
    patch_updates : make_list("ESXi410-201312401-SG", "ESXi410-201404401-SG")
  )
) flag++;

if (esx_check(ver:"ESXi 5.0", vib:"VMware:esx-base:5.0.0-2.38.1311177")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
