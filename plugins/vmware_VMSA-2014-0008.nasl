#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2014-0008. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(77630);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2013-0242", "CVE-2013-1914", "CVE-2013-4322", "CVE-2013-4590", "CVE-2014-0050", "CVE-2014-0114");
  script_bugtraq_id(57638, 58839, 63676, 64493, 65400, 65568, 65767, 65768, 66856, 66866, 66870, 66873, 66877, 66879, 66881, 66883, 66886, 66887, 66891, 66893, 66894, 66897, 66898, 66899, 66902, 66903, 66904, 66905, 66907, 66908, 66909, 66910, 66911, 66912, 66913, 66914, 66915, 66916, 66917, 66918, 66919, 66920, 67121);
  script_osvdb_id(89747, 92038, 102945, 103706, 103707, 106409);
  script_xref(name:"VMSA", value:"2014-0008");
  script_xref(name:"IAVB", value:"2014-B-0126");

  script_name(english:"VMSA-2014-0008 : VMware vSphere product updates to third-party libraries");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESXi host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. vCenter Server Apache Struts Update

   The Apache Struts library is updated to address a security issue.  

   This issue may lead to remote code execution after authentication.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the identifier CVE-2014-0114 to this issue.


b. vCenter Server tc-server 2.9.5 / Apache Tomcat 7.0.52 updates

   tc-server has been updated to version 2.9.5 to address multiple 
   security issues. This version of tc-server includes Apache Tomcat 
   7.0.52.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the identifiers CVE-2013-4590, CVE-2013-4322, and 
   CVE-2014-0050 to these issues. 

c. Update to ESXi glibc package

   glibc is updated to address multiple security issues.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the identifiers CVE-2013-0242 and CVE-2013-1914 to 
   these issues. 

d. vCenter and Update Manager, Oracle JRE 1.7 Update 55

   Oracle has documented the CVE identifiers that are addressed in 
   JRE 1.7.0 update 55 in the Oracle Java SE Critical Patch Update 
   Advisory of April 2014. The References section provides a link to
   this advisory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2014/000282.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts ClassLoader Manipulation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/11");
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


init_esx_check(date:"2014-09-09");
flag = 0;


if (esx_check(ver:"ESXi 5.1", vib:"VMware:esx-base:5.1.0-2.47.2323231")) flag++;

if (esx_check(ver:"ESXi 5.5", vib:"VMware:esx-base:5.5.0-1.30.1980513")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
