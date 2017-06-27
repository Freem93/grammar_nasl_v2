#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2008-0011. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(40380);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id("CVE-2006-4814", "CVE-2007-5001", "CVE-2007-6151", "CVE-2007-6206", "CVE-2008-0007", "CVE-2008-1105", "CVE-2008-1367", "CVE-2008-1375", "CVE-2008-1669");
  script_bugtraq_id(21663, 26701, 27497, 27686, 27705, 29076, 29404);
  script_osvdb_id(31377, 39243, 40913, 42716, 43548, 44874, 44929, 44987, 45657);
  script_xref(name:"VMSA", value:"2008-0011");

  script_name(english:"VMSA-2008-0011 : Updated ESX service console packages for Samba and vmnix");
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
"I   Service Console rpm updates

 a.  Security Update to Service Console Kernel

   This fix upgrades service console kernel version to 2.4.21-57.EL.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2007-5001, CVE-2007-6151, CVE-2007-6206,
   CVE-2008-0007, CVE-2008-1367, CVE-2008-1375, CVE-2006-4814, and
   CVE-2008-1669 to the security issues fixed in kernel-2.4.21-57.EL.

 b.  Samba Security Update

   This fix upgrades the service console rpm samba to version
   3.0.9-1.3E.15vmw

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2008-1105 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2008/000041.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 94, 119, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.5.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/20");
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


init_esx_check(date:"2008-07-28");
flag = 0;


if (esx_check(ver:"ESX 2.5.4", patch:"21")) flag++;

if (esx_check(ver:"ESX 2.5.5", patch:"10")) flag++;

if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1006028")) flag++;

if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1006029")) flag++;

if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200806201-UG",
    patch_updates : make_list("ESX350-200911201-UG", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200806218-UG",
    patch_updates : make_list("ESX350-200808218-UG", "ESX350-201008410-SG", "ESX350-201012408-SG", "ESX350-Update02", "ESX350-Update03", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
