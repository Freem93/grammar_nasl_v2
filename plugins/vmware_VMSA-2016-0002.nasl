#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2016-0002. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(88954);
  script_version("$Revision: 2.15 $");
  script_cvs_date("$Date: 2017/01/27 23:31:26 $");

  script_cve_id("CVE-2015-7547");
  script_osvdb_id(134584);
  script_xref(name:"TRA", value:"TRA-2017-08");
  script_xref(name:"IAVB", value:"2016-B-0036");
  script_xref(name:"IAVB", value:"2016-B-0037");
  script_xref(name:"VMSA", value:"2016-0002");

  script_name(english:"VMSA-2016-0002 : VMware product updates address a critical glibc security vulnerability");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESXi host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. glibc update for multiple products.

   The glibc library has been updated in multiple products to resolve 
   a stack-based buffer overflow present in the glibc getaddrinfo function.
  
   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the identifier CVE-2015-7547.

   VMware products have been grouped into the following four
   categories :
   
   I) ESXi and ESX Hypervisor
   Versions of ESXi and ESX prior to 5.5 are not affected because
   they do not ship with a vulnerable version of glibc.
   ESXi 5.5 and ESXi 6.0 ship with a vulnerable version of glibc and
   are affected. 
   See table 1 for remediation for ESXi 5.5 and ESXi 6.0.
 
   II) Windows-based products
   Windows-based products, including all versions of vCenter Server 
   running on Windows, are not affected.

   III) VMware virtual appliances
   VMware virtual appliances ship with a vulnerable version of glibc
   and are affected. 
   See table 2 for remediation for appliances.
   
   IV) Products that run on Linux
   VMware products that run on Linux (excluding virtual appliances)
   might use a vulnerable version of glibc as part of the base
   operating system. If the operating system has a vulnerable version
   of glibc, VMware recommends that customers contact their operating
   system vendor for resolution.  
   
   WORKAROUND

   Workarounds are available for several virtual appliances. These are 
   documented in VMware KB article 2144032.

   RECOMMENDATIONS

   VMware recommends customers evaluate and deploy patches for
   affected products in Table 1 and 2 below as these patches become
   available. In case patches are not available, customers are
   advised to deploy the workaround.

   Column 4 of the following tables lists the action required to
   remediate the vulnerability in each release, if a solution is
   available.

   Table 1 - ESXi
   =============="
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2016/000320.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2017-08"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/22");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/25");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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


init_esx_check(date:"2016-02-22");
flag = 0;


if (esx_check(ver:"ESXi 5.5", vib:"VMware:esx-base:5.5.0-3.84.3568722")) flag++;

if (esx_check(ver:"ESXi 6.0", vib:"VMware:esx-base:6.0.0-1.29.3568940")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
