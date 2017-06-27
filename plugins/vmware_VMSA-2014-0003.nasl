#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2014-0003. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(73469);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/07/08 22:17:25 $");

  script_cve_id("CVE-2014-1209", "CVE-2014-1210");
  script_bugtraq_id(66772, 66773);
  script_osvdb_id(105726, 105727);
  script_xref(name:"VMSA", value:"2014-0003");

  script_name(english:"VMSA-2014-0003 : VMware vSphere Client updates address security vulnerabilities");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESXi / ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. vSphere Client Insecure Client Download

   vSphere Client contains a vulnerability in accepting an updated 
   vSphere Client file from an untrusted source. The vulnerability may 
   allow a host to direct vSphere Client to download and execute an 
   arbitrary file from any URI. This issue can be exploited if 
   the host has been compromised or if a user has been tricked 
   into clicking a malicious link.

   VMware would like to thank Recurity Labs GmbH and the Bundesamt
Sicherheit
   in der Informationstechnik (BSI) for reporting this issue to us

   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the name CVE-2014-1209 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2014/000236.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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


init_esx_check(date:"2014-04-10");
flag = 0;


if (esx_check(ver:"ESX 4.0", patch:"ESX400-201404401-SG")) flag++;

if (esx_check(ver:"ESX 4.1", patch:"ESX410-201404401-SG")) flag++;

if (esx_check(ver:"ESXi 4.0", patch:"ESXi400-201402402-SG")) flag++;

if (esx_check(ver:"ESXi 4.1", patch:"ESXi410-201404401-SG")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
