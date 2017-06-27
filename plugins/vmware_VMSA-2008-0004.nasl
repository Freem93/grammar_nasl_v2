#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2008-0004. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(40375);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/06 17:22:02 $");

  script_cve_id("CVE-2007-5497");
  script_bugtraq_id(26772);
  script_osvdb_id(40161);
  script_xref(name:"VMSA", value:"2008-0004");

  script_name(english:"VMSA-2008-0004 : Low: Updated e2fsprogs service console package");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated e2fsprogs package address multiple integer overflow flaws

Thanks to Rafal Wojtczuk of McAfee Avert Research for identifying and
reporting this issue.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2007-5497 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2008/000010.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.5.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/27");
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


init_esx_check(date:"2008-03-03");
flag = 0;


if (esx_check(ver:"ESX 2.5.4", patch:"16")) flag++;

if (esx_check(ver:"ESX 2.5.5", patch:"5")) flag++;

if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1003517")) flag++;

if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1003523")) flag++;

if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200803214-UG",
    patch_updates : make_list("ESX350-Update01", "ESX350-Update02", "ESX350-Update03", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:esx_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
