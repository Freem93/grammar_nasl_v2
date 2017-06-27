#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2008-0010. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(40379);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id("CVE-2007-5232", "CVE-2007-5236", "CVE-2007-5237", "CVE-2007-5238", "CVE-2007-5239", "CVE-2007-5240", "CVE-2007-5274", "CVE-2007-5333", "CVE-2007-5342", "CVE-2007-5461", "CVE-2007-5689", "CVE-2007-6286", "CVE-2008-0657", "CVE-2008-1185", "CVE-2008-1186", "CVE-2008-1187", "CVE-2008-1188", "CVE-2008-1189", "CVE-2008-1190", "CVE-2008-1191", "CVE-2008-1192", "CVE-2008-1193", "CVE-2008-1194", "CVE-2008-1195", "CVE-2008-1196", "CVE-2008-4294");
  script_bugtraq_id(25918, 25920, 26070, 27006, 27650, 27706, 28083, 28125);
  script_osvdb_id(37759, 37760, 37761, 37762, 37763, 37764, 37765, 38187, 39833, 40834, 41146, 41147, 41435, 41436, 42589, 42590, 42591, 42592, 42593, 42594, 42595, 42596, 42597, 42598, 42599, 42600, 42601, 42602, 48610);
  script_xref(name:"VMSA", value:"2008-0010");

  script_name(english:"VMSA-2008-0010 : Updated Tomcat and Java JRE packages for VMware ESX 3.5 and VirtualCenter");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ESX patches and updates for VirtualCenter fix the following
application vulnerabilities.

 a. Tomcat Server Security Update

The ESX patches and the updates for VirtualCenter update the
Tomcat Server package to version 5.5.26, which addresses multiple
security issues that existed in earlier releases of Tomcat Server.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2007-5333, CVE-2007-5342, CVE-2007-5461,
CVE-2007-6286 to the security issues fixed in Tomcat 5.5.26.

 b. JRE Security Update

The ESX patches and the updates for VirtualCenter update the JRE
package to version 1.5.0_15, which addresses multiple security
issues that existed in earlier releases of JRE.

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the names CVE-2008-1185, CVE-2008-1186, CVE-2008-1187,
CVE-2008-1188, CVE-2008-1189, CVE-2008-1190, CVE-2008-1191,
CVE-2008-1192, CVE-2008-1193, CVE-2008-1194, CVE-2008-1195,
CVE-2008-1196, CVE-2008-0657, CVE-2007-5689, CVE-2007-5232,
CVE-2007-5236, CVE-2007-5237, CVE-2007-5238, CVE-2007-5239,
CVE-2007-5240, CVE-2007-5274 to the security issues fixed in
JRE 1.5.0_12, JRE 1.5.0_13, JRE 1.5.0_14, JRE 1.5.0_15."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2008/000031.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(22, 119, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/03");
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


init_esx_check(date:"2008-06-16");
flag = 0;


if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1004823")) flag++;

if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1006360")) flag++;

if (
  esx_check(
    ver           : "ESX 3.0.3",
    patch         : "ESX303-200808407-SG",
    patch_updates : make_list("ESX303-Rollup01", "ESX303-Update01")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200806404-SG",
    patch_updates : make_list("ESX350-201003403-SG", "ESX350-201203401-SG", "ESX350-Update02", "ESX350-Update03", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
