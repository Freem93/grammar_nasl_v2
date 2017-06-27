#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2012-0008. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(58903);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/06 17:22:02 $");

  script_cve_id("CVE-2010-4008", "CVE-2011-0216", "CVE-2011-1944", "CVE-2011-2834", "CVE-2011-3191", "CVE-2011-3905", "CVE-2011-3919", "CVE-2011-4348", "CVE-2012-0028");
  script_bugtraq_id(44779, 48056, 48832, 49295, 49658, 51084, 51300, 51363, 51947);
  script_osvdb_id(69205, 73248, 73994, 74910, 75560, 77707, 78148, 78303, 79098);
  script_xref(name:"VMSA", value:"2012-0008");

  script_name(english:"VMSA-2012-0008 : VMware ESX updates to ESX Service Console");
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
"a. ESX third-party update for Service Console kernel

   The ESX Service Console Operating System (COS) kernel is updated
   which addresses several security issues in the COS kernel.

   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the names CVE-2011-3191, CVE-2011-4348 and CVE-2012-0028 to
   these issues.

b. Updated ESX Service Console package libxml2

   The ESX Console Operating System (COS) libxml2 rpms are updated to
   the following versions libxml2-2.6.26-2.1.12.el5_7.2 and
   libxml2-python-2.6.26-2.1.12.el5_7.2 which addresses several
   security issues.

   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the names CVE-2010-4008, CVE-2011-0216, CVE-2011-1944,
   CVE-2011-2834, CVE-2011-3905, CVE-2011-3919 to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2012/000189.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/28");
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


init_esx_check(date:"2012-04-26");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201204401-SG",
    patch_updates : make_list("ESX410-201205401-SG", "ESX410-201206401-SG", "ESX410-201208101-SG", "ESX410-201211401-SG", "ESX410-201301401-SG", "ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201204402-SG",
    patch_updates : make_list("ESX410-201208102-SG", "ESX410-201301405-SG", "ESX410-201304402-SG", "ESX410-201307405-SG", "ESX410-Update03")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
