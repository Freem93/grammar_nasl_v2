#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2010-0010. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(47150);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id("CVE-2008-5029", "CVE-2008-5300", "CVE-2009-1337", "CVE-2009-1385", "CVE-2009-1895", "CVE-2009-2692", "CVE-2009-2698", "CVE-2009-2848", "CVE-2009-3002", "CVE-2009-3547");
  script_bugtraq_id(32154, 34405, 35185, 35647, 35930, 36038, 36108, 36176, 36901);
  script_osvdb_id(49946, 50272, 53629, 54892, 55807, 56992, 57264, 57428, 57462, 59654);
  script_xref(name:"VMSA", value:"2010-0010");

  script_name(english:"VMSA-2010-0010 : ESX 3.5 third-party update for Service Console kernel");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. Service Console update for COS kernel

   The service console package kernel is updated to version 2.4.21-63.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2008-5029, CVE-2008-5300, CVE-2009-1337,
   CVE-2009-1385, CVE-2009-1895, CVE-2009-2848, CVE-2009-3002, and
   CVE-2009-3547 to the security issues fixed in kernel-2.4.21-63.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2009-2698, CVE-2009-2692 to the security
   issues fixed in kernel-2.4.21-60."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2010/000098.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel Sendpage Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(16, 119, 189, 200, 264, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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


init_esx_check(date:"2010-06-24");
flag = 0;


if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201006401-SG")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
