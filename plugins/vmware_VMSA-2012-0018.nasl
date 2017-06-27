#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2012-0018. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(63332);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/05/06 17:22:02 $");

  script_cve_id("CVE-2009-5029", "CVE-2009-5064", "CVE-2010-0830", "CVE-2011-1089", "CVE-2011-4609", "CVE-2012-0864", "CVE-2012-3404", "CVE-2012-3405", "CVE-2012-3406", "CVE-2012-3480", "CVE-2012-6324", "CVE-2012-6325", "CVE-2012-6326");
  script_bugtraq_id(40063, 46740, 50898, 51439, 52201, 54374, 54982, 57021, 57022, 58139);
  script_osvdb_id(65077, 74278, 74883, 77508, 78316, 79705, 80719, 84710, 88150, 88151, 88152, 88631, 88632, 90580);
  script_xref(name:"VMSA", value:"2012-0018");

  script_name(english:"VMSA-2012-0018 : VMware security updates for vCSA and ESXi");
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
"a. vCenter Server Appliance directory traversal

   The vCenter Server Appliance (vCSA) contains a directory
   traversal vulnerability that allows an authenticated 
   remote user to retrieve arbitrary files. Exploitation of
   this issue may expose sensitive information stored on the 
   server. 

   VMware would like to thank Alexander Minozhenko from ERPScan for
   reporting this issue to us.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2012-6324 to this issue.

 b. vCenter Server Appliance arbitrary file download

   The vCenter Server Appliance (vCSA) contains an XML parsing 
   vulnerability that allows an authenticated remote user to
   retrieve arbitrary files.  Exploitation of this issue may
   expose sensitive information stored on the server.

   VMware would like to thank Alexander Minozhenko from ERPScan for
   reporting this issue to us.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2012-6325 to this issue.

 c. Update to ESX glibc package

   The ESX glibc package is updated to version glibc-2.5-81.el5_8.1
   to resolve multiple security issues.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2009-5029, CVE-2009-5064,
   CVE-2010-0830, CVE-2011-1089, CVE-2011-4609, CVE-2012-0864
   CVE-2012-3404, CVE-2012-3405, CVE-2012-3406 and CVE-2012-3480
   to these issues.

 d. vCenter Server and vCSA webservice logging denial of service

   The vCenter Server and vCenter Server Appliance (vCSA) both
   contain a vulnerability that allows unauthenticated remote 
   users to create abnormally large log entries.  Exploitation
   of this issue may allow an attacker to fill the system volume
   of the vCenter host or appliance VM and create a 
   denial-of-service condition. 

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2012-6326 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2013/000212.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:UR");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/24");
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


init_esx_check(date:"2012-12-20");
flag = 0;


if (esx_check(ver:"ESXi 5.0", vib:"VMware:esx-base:5.0.0-1.25.912577")) flag++;
if (esx_check(ver:"ESXi 5.0", vib:"VMware:tools-light:5.0.0-1.25.912577")) flag++;

if (esx_check(ver:"ESXi 5.1", vib:"VMware:esx-base:5.1.0-0.11.1063671")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
