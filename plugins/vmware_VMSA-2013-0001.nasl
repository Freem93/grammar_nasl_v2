#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2013-0001. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(64642);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2011-1202", "CVE-2011-3102", "CVE-2011-3970", "CVE-2012-2807", "CVE-2012-2825", "CVE-2012-2870", "CVE-2012-2871", "CVE-2012-4244", "CVE-2013-1405");
  script_bugtraq_id(47668, 51911, 53540, 54203, 54718, 55331, 55522, 57666);
  script_osvdb_id(72490, 78950, 81964, 83255, 83266, 85035, 85036, 85417, 89755, 91608);
  script_xref(name:"VMSA", value:"2013-0001");
  script_xref(name:"IAVA", value:"2013-A-0031");

  script_name(english:"VMSA-2013-0001 : VMware vSphere security updates for the authentication service and third-party libraries");
  script_summary(english:"Checks esxupdate output for the patches");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote VMware ESXi / ESX host is missing one or more
security-related patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. VMware vSphere client-side authentication memory corruption
   vulnerability

   VMware vCenter Server, vSphere Client, and ESX contain a
   vulnerability in the handling of the management authentication
   protocol. To exploit this vulnerability, an attacker must
   convince either vCenter Server, vSphere Client or ESX to
   interact with a malicious server as a client. Exploitation of
   the issue may lead to code execution on the client system.
     
   To reduce the likelihood of exploitation, vSphere components
   should be deployed on an isolated management network.
     
   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2013-1405 to this issue.

b. Update to ESX/ESXi libxml2 userworld and service console

   The ESX/ESXi userworld libxml2 library has been updated to
   resolve multiple security issues. Also, the ESX service console
   libxml2 packages are updated to the following versions :

     libxml2-2.6.26-2.1.15.el5_8.5
     libxml2-python-2.6.26-2.1.15.el5_8.5

   These updates fix multiple security issues. The Common
   Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the names CVE-2011-3102 and CVE-2012-2807 to these
   issues.

c. Update to ESX service console bind packages

   The ESX service console bind packages are updated to the
   following versions :

     bind-libs-9.3.6-20.P1.el5_8.2
     bind-utils-9.3.6-20.P1.el5_8.2

   These updates fix a security issue. The Common Vulnerabilities
   and Exposures project (cve.mitre.org) has assigned the name
   CVE-2012-4244 to this issue.

d. Update to ESX service console libxslt package

   The ESX service console libxslt package is updated to version
   libxslt-1.1.17-4.el5_8.3 to resolve multiple security issues.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2011-1202, CVE-2011-3970,
   CVE-2012-2825, CVE-2012-2870, and CVE-2012-2871 to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2013/000215.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/16");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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


init_esx_check(date:"2013-01-31");
flag = 0;


if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201302401-SG")) flag++;

if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201302401-SG",
    patch_updates : make_list("ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG")
  )
) flag++;
if (esx_check(ver:"ESX 4.0", patch:"ESX400-201305402-SG")) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201301401-SG",
    patch_updates : make_list("ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG")
  )
) flag++;
if (esx_check(ver:"ESX 4.1", patch:"ESX410-201301402-SG")) flag++;
if (esx_check(ver:"ESX 4.1", patch:"ESX410-201301403-SG")) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201301405-SG",
    patch_updates : make_list("ESX410-201304402-SG", "ESX410-201307405-SG")
  )
) flag++;

if (esx_check(ver:"ESXi 3.5.0", patch:"ESXe350-201302401-I-SG")) flag++;
if (esx_check(ver:"ESXi 3.5.0", patch:"ESXe350-201302403-C-SG")) flag++;

if (
  esx_check(
    ver           : "ESXi 4.0",
    patch         : "ESXi400-201302401-SG",
    patch_updates : make_list("ESXi400-201305401-SG", "ESXi400-201310401-SG", "ESXi400-201404401-SG")
  )
) flag++;
if (
  esx_check(
    ver           : "ESXi 4.0",
    patch         : "ESXi400-201302403-SG",
    patch_updates : make_list("ESXi400-201404402-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.1",
    patch         : "ESXi410-201301401-SG",
    patch_updates : make_list("ESXi410-201304401-SG", "ESXi410-201307401-SG", "ESXi410-201312401-SG", "ESXi410-201404401-SG")
  )
) flag++;

if (esx_check(ver:"ESXi 5.0", vib:"VMware:esx-base:5.0.0-2.29.1022489")) flag++;

if (esx_check(ver:"ESXi 5.1", vib:"VMware:esx-base:5.1.0-0.11.1063671")) flag++;
if (esx_check(ver:"ESXi 5.1", vib:"VMware:esx-xserver:5.1.0-0.11.1063671")) flag++;
if (esx_check(ver:"ESXi 5.1", vib:"VMware:net-bnx2x:1.61.15.v50.3-1vmw.510.0.11.1063671")) flag++;
if (esx_check(ver:"ESXi 5.1", vib:"VMware:tools-light:5.1.0-0.11.1063671")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
