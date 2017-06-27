#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2014-0012. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(79762);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2013-1752", "CVE-2013-2877", "CVE-2013-4238", "CVE-2014-0015", "CVE-2014-0138", "CVE-2014-0191", "CVE-2014-3797", "CVE-2014-8371");
  script_bugtraq_id(61050, 61738, 63804, 65270, 66457, 67233, 71492, 71493);
  script_xref(name:"VMSA", value:"2014-0012");
  script_xref(name:"IAVB", value:"2014-B-0161");

  script_name(english:"VMSA-2014-0012 : VMware vSphere product updates address security vulnerabilities");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESXi host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. VMware vCSA cross-site scripting vulnerability

   VMware vCenter Server Appliance (vCSA) contains a vulnerability
   that may allow for Cross Site Scripting. Exploitation of this 
   vulnerability in vCenter Server requires tricking a user to click
   on a malicious link or to open a malicious web page. 

   VMware would like to thank Tanya Secker of Trustwave SpiderLabs for 
   reporting this issue to us. 

   The Common Vulnerabilities and Exposures project (cve.mitre.org) 
   has assigned the name CVE-2014-3797 to this issue. 

b. vCenter Server certificate validation issue

   vCenter Server does not properly validate the presented certificate 
   when establishing a connection to a CIM Server residing on an ESXi 
   host. This may allow for a Man-in-the-middle attack against the CIM 
   service.

   VMware would like to thank The Google Security Team for reporting 
   this issue to us.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the identifier CVE-2014-8371 to this issue. 

  c. Update to ESXi libxml2 package

  libxml2 is updated to address multiple security issues. 

  The Common Vulnerabilities and Exposures project 
  (cve.mitre.org) has assigned the names CVE-2013-2877 and
  CVE-2014-0191 to these issues. 

  d. Update to ESXi Curl package

  Curl is updated to address multiple security issues. 

  The Common Vulnerabilities and Exposures project 
  (cve.mitre.org) has assigned the names CVE-2014-0015 and 
  CVE-2014-0138 to these issues. 

  e. Update to ESXi Python package

  Python is updated to address multiple security issues. 

  The Common Vulnerabilities and Exposures project 
  (cve.mitre.org) has assigned the names CVE-2013-1752 and 
  CVE-2013-4238 to these issues. 

  f. vCenter and Update Manager, Oracle JRE 1.6 Update 81

  Oracle has documented the CVE identifiers that are addressed in 
  JRE 1.6.0 update 81 in the Oracle Java SE Critical Patch Update
  Advisory of July 2014. The References section provides a link to
  this advisory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2015/000287.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/06");
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


init_esx_check(date:"2014-12-04");
flag = 0;


if (esx_check(ver:"ESXi 5.1", vib:"VMware:esx-base:5.1.0-2.47.2323231")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:esx_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
