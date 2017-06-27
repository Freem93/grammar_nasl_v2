#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2010-0017. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(50858);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2016/05/19 18:10:50 $");

  script_cve_id("CVE-2010-3081");
  script_bugtraq_id(38027, 38144, 39719, 43239);
  script_osvdb_id(62045, 62168, 62379, 62380, 63630, 63631, 64549, 68213);
  script_xref(name:"VMSA", value:"2010-0017");

  script_name(english:"VMSA-2010-0017 : VMware ESX third-party update for Service Console kernel");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. Service Console OS update for COS kernel package.

   This patch updates the Service Console kernel to fix a stack
   pointer underflow issue in the 32-bit compatibility layer.

   Exploitation of this issue could allow a local user to gain
   additional privileges.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2010-3081 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2011/000117.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/01");
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


init_esx_check(date:"2010-11-29");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201101401-SG",
    patch_updates : make_list("ESX400-201103401-SG", "ESX400-201104401-SG", "ESX400-201110401-SG", "ESX400-201111201-SG", "ESX400-201203401-SG", "ESX400-201205401-SG", "ESX400-201206401-SG", "ESX400-201209401-SG", "ESX400-201302401-SG", "ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201011402-SG",
    patch_updates : make_list("ESX40-TO-ESX41UPDATE01", "ESX410-201101201-SG", "ESX410-201104401-SG", "ESX410-201110201-SG", "ESX410-201201401-SG", "ESX410-201204401-SG", "ESX410-201205401-SG", "ESX410-201206401-SG", "ESX410-201208101-SG", "ESX410-201211401-SG", "ESX410-201301401-SG", "ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG", "ESX410-Update01", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
