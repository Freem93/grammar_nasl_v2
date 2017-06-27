#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2014-0006. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(74465);
  script_version("$Revision: 1.40 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2010-5298", "CVE-2014-0198", "CVE-2014-0224", "CVE-2014-3470");
  script_bugtraq_id(67899);
  script_osvdb_id(102200, 105763, 106531, 107731);
  script_xref(name:"VMSA", value:"2014-0006");
  script_xref(name:"IAVB", value:"2014-B-0088");
  script_xref(name:"IAVB", value:"2014-B-0089");
  script_xref(name:"IAVB", value:"2014-B-0097");

  script_name(english:"VMSA-2014-0006 : VMware product updates address OpenSSL security vulnerabilities");
  script_summary(english:"Checks esxupdate output for the patches");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote VMware ESXi host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. OpenSSL update for multiple products.

   OpenSSL libraries have been updated in multiple products to
   versions 0.9.8za and 1.0.1h in order to resolve multiple security
   issues.
 
   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2014-0224, CVE-2014-0198,
   CVE-2010-5298, CVE-2014-3470, CVE-2014-0221 and CVE-2014-0195 to
   these issues. The most important of these issues is
   CVE-2014-0224.

   CVE-2014-0198, CVE-2010-5298 and CVE-2014-3470 are considered to
   be of moderate severity. Exploitation is highly unlikely or is
   mitigated due to the application configuration.

   CVE-2014-0221 and CVE-2014-0195, which are listed in the OpenSSL 
   Security Advisory (see Reference section below), do not affect
   any VMware products.     

   CVE-2014-0224 may lead to a Man-in-the-Middle attack if a server
   is running a vulnerable version of OpenSSL 1.0.1 and clients are
   running a vulnerable version of OpenSSL 0.9.8 or 1.0.1. Updating
   the server will mitigate this issue for both the server and all
   affected clients.

   CVE-2014-0224 may affect products differently depending on
   whether the product is acting as a client or a server and of
   which version of OpenSSL the product is using. For readability
   the affected products have been split into 3 tables below, 
   based on the different client-server configurations and
   deployment scenarios.

   MITIGATIONS

   Clients that communicate with a patched or non-vulnerable server
   are not vulnerable to CVE-2014-0224. Applying these patches to 
   affected servers will mitigate the affected clients (See Table 1
   below).

   Clients that communicate over untrusted networks such as public
   Wi-Fi and communicate to a server running a vulnerable version of 
   OpenSSL 1.0.1. can be mitigated by using a secure network such as 
   VPN (see Table 2 below).
   
   Clients and servers that are deployed on an isolated network are
   less exposed to CVE-2014-0224 (see Table 3 below). The affected
   products are typically deployed to communicate over the
   management network. 

   RECOMMENDATIONS

   VMware recommends customers evaluate and deploy patches for
   affected Servers in Table 1 below as these patches become
   available. Patching these servers will remove the ability to
   exploit the vulnerability described in CVE-2014-0224 on both
   clients and servers. 

   VMware recommends customers consider 
   applying patches to products listed in Table 2 &amp; 3 as required.

   Column 4 of the following tables lists the action required to
   remediate the vulnerability in each release, if a solution is
   available.

   Table 1
   =======
   Affected servers running a vulnerable version of OpenSSL 1.0.1."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2014/000276.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/11");
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


init_esx_check(date:"2014-06-10");
flag = 0;


if (esx_check(ver:"ESXi 5.0", vib:"VMware:esx-base:5.0.0-3.50.1918656")) flag++;

if (esx_check(ver:"ESXi 5.1", vib:"VMware:esx-base:5.1.0-2.29.1900470")) flag++;
if (esx_check(ver:"ESXi 5.1", vib:"VMware:esx-tboot:5.1.0-2.23.1483097")) flag++;
if (esx_check(ver:"ESXi 5.1", vib:"VMware:misc-drivers:5.1.0-2.23.1483097")) flag++;

if (esx_check(ver:"ESXi 5.5", vib:"VMware:esx-base:5.5.0-1.18.1881737")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:esx_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
