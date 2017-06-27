#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2012-0003. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(58302);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/19 18:10:50 $");

  script_cve_id("CVE-2011-3389", "CVE-2011-3516", "CVE-2011-3521", "CVE-2011-3544", "CVE-2011-3545", "CVE-2011-3546", "CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3549", "CVE-2011-3550", "CVE-2011-3551", "CVE-2011-3552", "CVE-2011-3553", "CVE-2011-3554", "CVE-2011-3555", "CVE-2011-3556", "CVE-2011-3557", "CVE-2011-3558", "CVE-2011-3560", "CVE-2011-3561");
  script_bugtraq_id(49778, 50211, 50215, 50216, 50218, 50220, 50223, 50224, 50226, 50229, 50231, 50234, 50236, 50237, 50239, 50242, 50243, 50246, 50248, 50250);
  script_osvdb_id(74829, 76495, 76496, 76497, 76498, 76499, 76500, 76501, 76502, 76503, 76504, 76505, 76506, 76507, 76508, 76509, 76510, 76511, 76512, 76513);
  script_xref(name:"VMSA", value:"2012-0003");

  script_name(english:"VMSA-2012-0003 : VMware VirtualCenter Update and ESX 3.5 patch update JRE");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. VirtualCenter and ESX, Oracle (Sun) JRE update 1.5.0_32

   Oracle (Sun) JRE is updated to version 1.5.0_32, which addresses
   multiple security issues that existed in earlier releases of Oracle
   (Sun) JRE.

   Oracle has documented the CVE identifiers that are addressed in
   JRE 1.5.0_32 in the Oracle Java SE Critical Patch Update Advisory of
   October 2011."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2012/000187.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Rhino Script Engine Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/09");
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


init_esx_check(date:"2012-03-08");
flag = 0;


if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201203401-SG")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
