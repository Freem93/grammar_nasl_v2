#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2012-0006. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(58535);
  script_version("$Revision: 1.36 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2011-2482", "CVE-2011-3191", "CVE-2011-4348", "CVE-2011-4862", "CVE-2012-1515");
  script_bugtraq_id(49295, 49373, 51182, 51300, 51363, 51947, 52820);
  script_osvdb_id(74910, 75240, 78020, 78303, 80727);
  script_xref(name:"VMSA", value:"2012-0006");
  script_xref(name:"IAVA", value:"2012-A-0056");

  script_name(english:"VMSA-2012-0006 : VMware Workstation, ESXi, and ESX address several security issues");
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
"a. VMware ROM Overwrite Privilege Escalation
 
   A flaw in the way port-based I/O is handled allows for modifying
   Read-Only Memory that belongs to the Virtual DOS Machine.
   Exploitation of this issue may lead to privilege escalation on
   Guest Operating Systems that run Windows 2000, Windows XP
   32-bit, Windows Server 2003 32-bit or Windows Server 2003 R2
   32-bit.
 
   VMware would like to thank Derek Soeder of Ridgeway Internet
   Security, L.L.C. for reporting this issue to us.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2012-1515 to this issue.
 
b. ESX third-party update for Service Console kernel
 
   The ESX Service Console Operating System (COS) kernel is updated
   to kernel-400.2.6.18-238.4.11.591731 to fix multiple security
   issues in the COS kernel.
 
   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2011-2482, CVE-2011-3191 and
   CVE-2011-4348 to these issues.
 
c. ESX third-party update for Service Console krb5 RPM
 
   This patch updates the krb5-libs and krb5-workstation RPMs to
   version 1.6.1-63.el5_7 to resolve a security issue.
 
   By default, the affected krb5-telnet and ekrb5-telnet services
   do not run. The krb5 telnet daemon is an xinetd service.  You
   can run the following commands to check if krb5 telnetd is
   enabled :

     /sbin/chkconfig --list krb5-telnet
     /sbin/chkconfig --list ekrb5-telnet
  
   The output of these commands displays if krb5 telnet is enabled.
  
   You can run the following commands to disable krb5 telnet
   daemon :

     /sbin/chkconfig krb5-telnet off
     /sbin/chkconfig ekrb5-telnet off
 
   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2011-4862 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2012/000180.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-760");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux BSD-derived Telnet Service Encryption Key ID Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/30");
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


init_esx_check(date:"2012-03-29");
flag = 0;


if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201203401-SG")) flag++;

if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201203401-SG",
    patch_updates : make_list("ESX400-201205401-SG", "ESX400-201206401-SG", "ESX400-201209401-SG", "ESX400-201302401-SG", "ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG")
  )
) flag++;
if (esx_check(ver:"ESX 4.0", patch:"ESX400-201203407-SG")) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201101201-SG",
    patch_updates : make_list("ESX40-TO-ESX41UPDATE01", "ESX410-201104401-SG", "ESX410-201110201-SG", "ESX410-201201401-SG", "ESX410-201204401-SG", "ESX410-201205401-SG", "ESX410-201206401-SG", "ESX410-201208101-SG", "ESX410-201211401-SG", "ESX410-201301401-SG", "ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG", "ESX410-Update01", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;

if (esx_check(ver:"ESXi 3.5.0", patch:"ESXe350-201203401-I-SG")) flag++;

if (
  esx_check(
    ver           : "ESXi 4.0",
    patch         : "ESXi400-201203401-SG",
    patch_updates : make_list("ESXi400-201205401-SG", "ESXi400-201206401-SG", "ESXi400-201209401-SG", "ESXi400-201302401-SG", "ESXi400-201305401-SG", "ESXi400-201310401-SG", "ESXi400-201404401-SG")
  )
) flag++;

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
