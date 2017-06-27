#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2014-0010. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(78025);
  script_version("$Revision: 1.33 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2014-6271", "CVE-2014-6277", "CVE-2014-6278", "CVE-2014-7169", "CVE-2014-7186", "CVE-2014-7187");
  script_bugtraq_id(70103, 70137, 70152, 70154, 70165, 70166);
  script_osvdb_id(112004, 112096, 112097);
  script_xref(name:"VMSA", value:"2014-0010");
  script_xref(name:"IAVA", value:"2014-A-0142");

  script_name(english:"VMSA-2014-0010 : VMware product updates address critical Bash security vulnerabilities (Shellshock)");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. Bash update for multiple products.

   Bash libraries have been updated in multiple products to resolve 
   multiple critical security issues, also referred to as Shellshock.
  
   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the identifiers CVE-2014-6271, CVE-2014-7169, 
   CVE-2014-7186, and CVE-2014-7187, CVE-2014-6277, CVE-2014-6278 
   to these issues.

   VMware products have been grouped into the following four
   product categories :
   
   I) ESXi and ESX Hypervisor
   ESXi is not affected because ESXi uses the Ash shell (through
   busybox), which is not affected by the vulnerability reported
   for the Bash shell.
   ESX has an affected version of the Bash shell. See table 1 for
   remediation for ESX.
 
   II) Windows-based products
   Windows-based products, including all versions of vCenter Server 
   running on Windows, are not affected.

   III) VMware (virtual) appliances
   VMware (virtual) appliances ship with an affected version of Bash. 
   See table 2 for remediation for appliances.
   
   IV) Products that run on Linux, Android, OSX or iOS (excluding 
   virtual appliances)

   Products that run on Linux, Android, OSX or iOS (excluding 
   virtual appliances) might use the Bash shell that is part of the
   operating system. If the operating system has a vulnerable
   version of Bash, the Bash security vulnerability might be
   exploited through the product. VMware recommends that customers
   contact their operating system vendor for a patch.    
   
   MITIGATIONS

   VMware encourages restricting access to appliances through
   firewall rules and other network layer controls to only trusted IP
   addresses. This measure will greatly reduce any risk to these
   appliances.

   RECOMMENDATIONS

   VMware recommends customers evaluate and deploy patches for
   affected products in Table 1 and 2 below as these
   patches become available. 

   For several products, both a patch and a product update are
available.
   In general, if a patch is  made available, the patch must be applied 
   to the latest version of the appliance.

   Customers should refer to the specific product Knowledge Base
articles 
   listed in Section 4 to understand the type of remediation available
and 
   applicable appliance version numbers.

   Column 4 of the following tables lists the action required to
   remediate the vulnerability in each release, if a solution is
   available.

   Table 1 - ESXi and ESX Hypervisor
   ================================="
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2014/000278.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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


init_esx_check(date:"2014-09-30");
flag = 0;


if (esx_check(ver:"ESX 4.0", patch:"ESX400-201410401-SG")) flag++;

if (esx_check(ver:"ESX 4.1", patch:"ESX410-201410401-SG")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
