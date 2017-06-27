#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2008-0002. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(40373);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id("CVE-2005-2090", "CVE-2006-7195", "CVE-2007-0450", "CVE-2007-2788");
  script_bugtraq_id(13873, 22960, 24004, 28481);
  script_osvdb_id(34769, 34887, 36199, 43452);
  script_xref(name:"VMSA", value:"2008-0002");

  script_name(english:"VMSA-2008-0002 : Low severity security update for VirtualCenter and ESX");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated VirtualCenter fixes the following application vulnerabilities

a. Tomcat Server Security Update
This release of VirtualCenter Server updates the Tomcat Server
package from 5.5.17 to 5.5.25, which addresses multiple security
issues that existed in the earlier releases of Tomcat Server.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the names CVE-2005-2090, CVE-2006-7195, and CVE-2007-0450 to
these issues.

b. JRE Security Update
This release of VirtualCenter Server updates the JRE package from
1.5.0_7 to 1.5.0_12, which addresses a security issue that existed in
the earlier release of JRE.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2007-3004 to this issue.

NOTE: These vulnerabilities can be exploited remotely only if the
      attacker has access to the service console network.

      Security best practices provided by VMware recommend that the
      service console be isolated from the VM network. Please see
      http://www.vmware.com/resources/techresources/726 for more
      information on VMware security best practices."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2008/000013.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/01");
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


init_esx_check(date:"2008-01-07");
flag = 0;


if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1003176")) flag++;

if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1002434")) flag++;

if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200803215-UG",
    patch_updates : make_list("ESX350-201003403-SG", "ESX350-201203401-SG", "ESX350-Update01", "ESX350-Update02", "ESX350-Update03", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:esx_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
