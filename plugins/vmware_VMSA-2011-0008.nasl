#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2011-0008. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(53840);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2011-0426", "CVE-2011-1788", "CVE-2011-1789");
  script_bugtraq_id(47735, 47742, 47744);
  script_osvdb_id(72178, 72179, 73866);
  script_xref(name:"VMSA", value:"2011-0008");
  script_xref(name:"IAVA", value:"2011-A-0066");

  script_name(english:"VMSA-2011-0008 : VMware vCenter Server and vSphere Client security vulnerabilities");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESXi / ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. vCenter Server Directory Traversal vulnerability

  A directory traversal vulnerability allows an attacker to remotely
  retrieve files from vCenter Server without authentication. In order
  to exploit this vulnerability, the attacker will need to have access
  to the network on which the vCenter Server host resides.

  In case vCenter Server is installed on Windows 2008 or
  Windows 2008 R2, the security vulnerability is not present.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2011-0426 to this issue.

b. vCenter Server SOAP ID disclosure

  The SOAP session ID can be retrieved by any user that is logged in
  to vCenter Server. This might allow a local unprivileged user on
  vCenter Server to elevate his or her privileges.

  VMware would like to thank Claudio Criscione for reporting this
  issue to us.

  The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CVE-2011-1788 to this issue.

c. vSphere Client Installer package not digitally signed

  The digitally signed vSphere Client installer is packaged in a
  self-extracting installer package which is not digitally signed. As
  a result, when you run the install package file to extract and start
  installing, the vSphere Client installer may display a Windows
  warning message stating that the publisher of the install package
  cannot be verified.
 
  The vSphere Client Installer package of the following product
  versions is now digitally signed :

    vCenter Server 4.1 Update 1
    vCenter Server 4.0 Update 3

    ESXi 4.1 Update 1
    ESXi 4.0 with patch ESXi400-201103402-SG

    ESX 4.1 Update 1
    ESX 4.0 with patch ESX400-201103401-SG

  An install or update of the vSphere Client from these releases will
  not present a security warning from Windows.
  Note: typically the vSphere Client will request an update if the
  existing client is pointed at a newer version of vCenter or ESX.

  VMware Knowledge Base article 1021404 explains how the unsigned
  install package can be obtained in an alternative, secure way for an
  environment with VirtualCenter 2.5, ESXi/ESX 3.5 or ESX 3.0.3.

  VMware would like to thank Claudio Criscione for reporting this
  issue to us.

  The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CVE-2011-1789 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2011/000137.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/09");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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


init_esx_check(date:"2011-05-05");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201103401-SG",
    patch_updates : make_list("ESX400-201104401-SG", "ESX400-201110401-SG", "ESX400-201111201-SG", "ESX400-201203401-SG", "ESX400-201205401-SG", "ESX400-201206401-SG", "ESX400-201209401-SG", "ESX400-201302401-SG", "ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.0",
    patch         : "ESXi400-201103402-SG",
    patch_updates : make_list("ESXi400-201302403-SG", "ESXi400-201404402-SG", "ESXi400-Update03")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:esx_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
