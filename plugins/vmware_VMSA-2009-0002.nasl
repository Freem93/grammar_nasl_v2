#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2009-0002. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(42178);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id("CVE-2008-1232", "CVE-2008-1947", "CVE-2008-2370");
  script_bugtraq_id(29502, 30494, 30496);
  script_osvdb_id(45905, 47462, 47463);
  script_xref(name:"VMSA", value:"2009-0002");

  script_name(english:"VMSA-2009-0002 : VirtualCenter Update 4 and ESX patch update Tomcat to version 5.5.27");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. Update for VirtualCenter and ESX patch update Apache Tomcat version
   to 5.5.27

  Update for VirtualCenter and ESX patch update the Tomcat package to
  version 5.5.27 which addresses multiple security issues that existed
  in the previous version of Apache Tomcat.

  The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the names CVE-2008-1232, CVE-2008-1947 and
  CVE-2008-2370 to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2009/000072.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/19");
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


init_esx_check(date:"2009-02-23");
flag = 0;


if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200910403-SG",
    patch_updates : make_list("ESX350-201003403-SG", "ESX350-201203401-SG", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:esx_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
