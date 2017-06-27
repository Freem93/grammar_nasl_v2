#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2013-0016. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(71617);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/07/15 10:43:53 $");

  script_cve_id("CVE-2013-5973");
  script_bugtraq_id(64491);
  script_osvdb_id(101387);
  script_xref(name:"VMSA", value:"2013-0016");

  script_name(english:"VMSA-2013-0016 : VMware ESXi and ESX unauthorized file access through vCenter Server and ESX");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESXi / ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:"a. VMware ESXi and ESX unauthorized file access through vCenter Server and"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2013/000229.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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


init_esx_check(date:"2013-12-22");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201310401-SG",
    patch_updates : make_list("ESX400-201404401-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201312401-SG",
    patch_updates : make_list("ESX410-201404401-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.0",
    patch         : "ESXi400-201310401-SG",
    patch_updates : make_list("ESXi400-201404401-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.1",
    patch         : "ESXi410-201312401-SG",
    patch_updates : make_list("ESXi410-201404401-SG")
  )
) flag++;

if (esx_check(ver:"ESXi 5.0", vib:"VMware:esx-base:5.0.0-2.38.1311177")) flag++;

if (esx_check(ver:"ESXi 5.1", vib:"VMware:esx-base:5.1.0-1.19.1312874")) flag++;

if (esx_check(ver:"ESXi 5.5", vib:"VMware:esx-base:5.5.0-0.7.1474526")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:esx_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
