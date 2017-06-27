#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2013-0003. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(64812);
  script_version("$Revision: 1.31 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2012-2110", "CVE-2013-1659");
  script_bugtraq_id(53158, 55501, 56025, 56033, 56039, 56043, 56046, 56051, 56054, 56055, 56056, 56057, 56058, 56059, 56061, 56063, 56065, 56066, 56067, 56068, 56070, 56071, 56072, 56075, 56076, 56078, 56079, 56080, 56081, 56082, 56083, 58115);
  script_osvdb_id(81223, 86344, 86345, 86346, 86347, 86348, 86349, 86350, 86351, 86352, 86353, 86354, 86355, 86356, 86357, 86358, 86359, 86360, 86361, 86362, 86363, 86364, 86365, 86366, 86367, 86368, 86369, 86370, 86371, 86372, 86374, 90554);
  script_xref(name:"VMSA", value:"2013-0003");
  script_xref(name:"IAVA", value:"2013-A-0053");
  script_xref(name:"IAVA", value:"2013-A-0055");

  script_name(english:"VMSA-2013-0003 : VMware vCenter Server, ESXi and ESX address an NFC Protocol memory corruption and third-party library security issues.");
  script_summary(english:"Checks esxupdate output for the patches");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote VMware ESXi / ESX host is missing one or more
security-related patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. VMware vCenter, ESXi and ESX NFC protocol memory corruption
   vulnerability

   VMware vCenter Server, ESXi and ESX contain a vulnerability in the
   handling of the Network File Copy (NFC) protocol. To exploit this
   vulnerability, an attacker must intercept and modify the NFC 
   traffic between vCenter Server and the client or ESXi/ESX and the
   client.  Exploitation of the issue may lead to code execution.

   To reduce the likelihood of exploitation, vSphere components should
   be deployed on an isolated management network

   VMware would like to thank Alex Chapman of Context Information
   Security for reporting this issue to us. 

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2013-1659 to this issue.

b. VirtualCenter, ESX and ESXi Oracle (Sun) JRE update 1.5.0_38

   Oracle (Sun) JRE is updated to version 1.5.0_38, which addresses
   multiple security issues that existed in earlier releases of
   Oracle (Sun) JRE. 

   Oracle has documented the CVE identifiers that are addressed
   in JRE 1.5.0_38 in the Oracle Java SE Critical Patch Update
   Advisory of October 2012. 

c. Update to ESX service console OpenSSL RPM 

   The service console OpenSSL RPM is updated to version 
   openssl-0.9.7a.33.28.i686 to resolve multiple security issues. 

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2012-2110 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2013/000205.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet JAX-WS Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");
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


init_esx_check(date:"2013-02-21");
flag = 0;


if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201302401-SG")) flag++;

if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201302401-SG",
    patch_updates : make_list("ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201301401-SG",
    patch_updates : make_list("ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG")
  )
) flag++;

if (esx_check(ver:"ESXi 3.5.0", patch:"ESXe350-201302401-I-SG")) flag++;
if (esx_check(ver:"ESXi 3.5.0", patch:"ESXe350-201302403-C-SG")) flag++;

if (
  esx_check(
    ver           : "ESXi 4.0",
    patch         : "ESXi400-201302401-SG",
    patch_updates : make_list("ESXi400-201305401-SG", "ESXi400-201310401-SG", "ESXi400-201404401-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.1",
    patch         : "ESXi410-201301401-SG",
    patch_updates : make_list("ESXi410-201304401-SG", "ESXi410-201307401-SG", "ESXi410-201312401-SG", "ESXi410-201404401-SG")
  )
) flag++;

if (esx_check(ver:"ESXi 5.0", vib:"VMware:tools-light:5.0.0-1.25.912577")) flag++;

if (esx_check(ver:"ESXi 5.1", vib:"VMware:esx-base:5.1.0-0.8.911593")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
