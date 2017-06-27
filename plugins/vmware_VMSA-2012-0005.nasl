#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2012-0005. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(58362);
  script_version("$Revision: 1.47 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2010-0405", "CVE-2011-3190", "CVE-2011-3375", "CVE-2011-3389", "CVE-2011-3546", "CVE-2011-3547", "CVE-2011-3554", "CVE-2012-0022", "CVE-2012-1508", "CVE-2012-1510", "CVE-2012-1512");
  script_bugtraq_id(43331, 49353, 49778, 50211, 50215, 50216, 50218, 50220, 50223, 50224, 50226, 50229, 50231, 50234, 50236, 50237, 50239, 50242, 50243, 50246, 50248, 50250, 51447, 52525);
  script_osvdb_id(68167, 74818, 74829, 76495, 76496, 76497, 76498, 76499, 76500, 76501, 76502, 76503, 76504, 76505, 76506, 76507, 76508, 76509, 76510, 76511, 76512, 76513, 78331, 78573, 80115, 80116, 80117, 80119, 80120, 80121);
  script_xref(name:"VMSA", value:"2012-0005");
  script_xref(name:"IAVA", value:"2012-A-0045");
  script_xref(name:"IAVA", value:"2012-A-0046");
  script_xref(name:"IAVB", value:"2010-B-0083");

  script_name(english:"VMSA-2012-0005 : VMware vCenter Server, Orchestrator, Update Manager, vShield, vSphere Client, Workstation, Player, ESXi, and ESX address several security issues");
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
"a. VMware Tools Display Driver Privilege Escalation

 The VMware XPDM and WDDM display drivers contain buffer overflow
 vulnerabilities and the XPDM display driver does not properly
 check for NULL pointers. Exploitation of these issues may lead
 to local privilege escalation on Windows-based Guest Operating
 Systems.

 VMware would like to thank Tarjei Mandt for reporting theses
 issues to us.

 The Common Vulnerabilities and Exposures project (cve.mitre.org)
 has assigned the names CVE-2012-1509 (XPDM buffer overrun),
 CVE-2012-1510 (WDDM buffer overrun) and CVE-2012-1508 (XPDM null
 pointer dereference) to these issues.

 Note: CVE-2012-1509 doesn't affect ESXi and ESX.

b. vSphere Client internal browser input validation vulnerability

 The vSphere Client has an internal browser that renders html
 pages from log file entries. This browser doesn't properly
 sanitize input and may run script that is introduced into the
 log files. In order for the script to run, the user would need
 to open an individual, malicious log file entry. The script
 would run with the permissions of the user that runs the vSphere
 Client.

 VMware would like to thank Edward Torkington for reporting this
 issue to us.

 The Common Vulnerabilities and Exposures project (cve.mitre.org)
 has assigned the name CVE-2012-1512 to this issue.

 In order to remediate the issue, the vSphere Client of the
 vSphere 5.0 Update 1 release or the vSphere 4.1 Update 2 release
 needs to be installed. The vSphere Clients that come with
 vSphere 4.0 and vCenter Server 2.5 are not affected.

c. vCenter Orchestrator Password Disclosure

 The vCenter Orchestrator (vCO) Web Configuration tool reflects
 back the vCenter Server password as part of the webpage. This
 might allow the logged-in vCO administrator to retrieve the
 vCenter Server password.

 VMware would like to thank Alexey Sintsov from Digital Security
 Research Group for reporting this issue to us.

 The Common Vulnerabilities and Exposures project (cve.mitre.org)
 has assigned the name CVE-2012-1513 to this issue.

d. vShield Manager Cross-Site Request Forgery vulnerability

 The vShield Manager (vSM) interface has a Cross-Site Request
 Forgery vulnerability. If an attacker can convince an
 authenticated user to visit a malicious link, the attacker may
 force the victim to forward an authenticated request to the
 server.

 VMware would like to thank Frans Pehrson of Xxor AB
 (www.xxor.se<http://www.xxor.se>) and Claudio Criscione for independently reporting
 this issue to us

 The Common Vulnerabilities and Exposures project (cve.mitre.org)
 has assigned the name CVE-2012-1514 to this issue.

e. vCenter Update Manager, Oracle (Sun) JRE update 1.6.0_30

 Oracle (Sun) JRE is updated to version 1.6.0_30, which addresses
 multiple security issues that existed in earlier releases of
 Oracle (Sun) JRE.

 Oracle has documented the CVE identifiers that are addressed in
 JRE 1.6.0_29 and JRE 1.6.0_30 in the Oracle Java SE Critical
 Patch Update Advisory of October 2011. The References section
 provides a link to this advisory.

f. vCenter Server Apache Tomcat update 6.0.35

 Apache Tomcat has been updated to version 6.0.35 to address
 multiple security issues.

 The Common Vulnerabilities and Exposures project (cve.mitre.org)
 has assigned the names CVE-2011-3190, CVE-2011-3375,
 CVE-2011-4858, and CVE-2012-0022 to these issues.


g. ESXi update to third-party component bzip2

 The bzip2 library is updated to version 1.0.6, which resolves a
 security issue.

 The Common Vulnerabilities and Exposures project (cve.mitre.org)
 has assigned the name CVE-2010-0405 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2012/000198.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Rhino Script Engine Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/16");
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


init_esx_check(date:"2012-03-15");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201110401-SG",
    patch_updates : make_list("ESX400-201111201-SG", "ESX400-201203401-SG", "ESX400-201205401-SG", "ESX400-201206401-SG", "ESX400-201209401-SG", "ESX400-201302401-SG", "ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG", "ESX400-Update04")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201110201-SG",
    patch_updates : make_list("ESX410-201201401-SG", "ESX410-201204401-SG", "ESX410-201205401-SG", "ESX410-201206401-SG", "ESX410-201208101-SG", "ESX410-201211401-SG", "ESX410-201301401-SG", "ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201208101-SG",
    patch_updates : make_list("ESX410-201211401-SG", "ESX410-201301401-SG", "ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG", "ESX410-Update03")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.1",
    patch         : "ESXi410-201110202-UG",
    patch_updates : make_list("ESXi410-Update02", "ESXi410-Update03")
  )
) flag++;

if (esx_check(ver:"ESXi 5.0", vib:"VMware:esx-base:5.0.0-0.10.608089")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
