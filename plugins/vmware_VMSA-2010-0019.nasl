#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2010-0019. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(51077);
  script_version("$Revision: 1.31 $");
  script_cvs_date("$Date: 2016/11/30 14:45:01 $");

  script_cve_id("CVE-2009-0590", "CVE-2009-2409", "CVE-2009-3555", "CVE-2010-0405", "CVE-2010-3069");
  script_bugtraq_id(34256, 36881, 36935, 43212, 43331);
  script_osvdb_id(52864, 56752, 61784, 67994, 68167);
  script_xref(name:"VMSA", value:"2010-0019");
  script_xref(name:"IAVB", value:"2010-B-0083");

  script_name(english:"VMSA-2010-0019 : VMware ESX third-party updates for Service Console");
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
"a. Service Console update for samba

   The service console package samba is updated to version
   3.0.9-1.3E.18.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2010-3069 to this issue.

b. Service Console update for bzip2

   The service console package bzip2 is updated to version
   1.0.2-14.EL3 in ESX 3.x and version 1.0.3-6 in ESX
   4.x.
  
   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2010-0405 to this issue.

c. Service Console update for OpenSSL

   The service console package openssl updated to version
   0.9.7a-33.26.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2009-0590, CVE-2009-2409 and
   CVE-2009-3555 to the issues addressed in this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2011/000134.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/08");
  script_set_attribute(attribute:"stig_severity", value:"II");
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


init_esx_check(date:"2010-12-07");
flag = 0;


if (esx_check(ver:"ESX 3.0.3", patch:"ESX303-201102402-SG")) flag++;

if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201012401-SG")) flag++;
if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201012408-SG")) flag++;
if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201012409-SG")) flag++;

if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201103405-SG",
    patch_updates : make_list("ESX400-Update03", "ESX400-Update04")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201104403-SG",
    patch_updates : make_list("ESX410-Update02", "ESX410-Update03")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
