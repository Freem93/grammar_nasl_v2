#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2014-0004. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(73851);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/05/12 14:45:23 $");

  script_cve_id("CVE-2014-0076", "CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(104810, 105465);
  script_xref(name:"VMSA", value:"2014-0004");

  script_name(english:"VMSA-2014-0004 : VMware product updates address OpenSSL security vulnerabilities");
  script_summary(english:"Checks esxupdate output for the patches");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote VMware ESXi host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. Information Disclosure vulnerability in OpenSSL third-party library

   The OpenSSL library is updated to version openssl-1.0.1g to 
   resolve multiple security issues.
 
   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the names CVE-2014-0076 and CVE-2014-0160 to these issues.

   CVE-2014-0160 is known as the Heartbleed issue. More information
   on this issue may be found in the reference section.

   To remediate the issue for products that have updated versions or 
   patches available, perform these steps: 

     * Deploy the VMware product update or product patches
     * Replace certificates per the product-specific documentation
     * Reset passwords per the product-specific documentation

   Section 4 lists product-specific references to installation 
   instructions and certificate management documentation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2014/000244.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'OpenSSL Heartbeat (Heartbleed) Information Leak');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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


init_esx_check(date:"2014-04-14");
flag = 0;

if (esx_check(ver:"ESXi 5.5", vib:"VMware:esx-base:5.5.0-1"))
{
  # Eliminate existing reportl not having update 1 is not an issue
  esx_report = '';
  if (esx_check(ver:"ESXi 5.5", vib:"VMware:esx-base:5.5.0-0.15.1746974")) flag++;
}
else
  if (esx_check(ver:"ESXi 5.5", vib:"VMware:esx-base:5.5.0-1.16.1746018")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
