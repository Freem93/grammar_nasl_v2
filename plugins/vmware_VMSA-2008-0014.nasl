#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2008-0014. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(40382);
  script_version("$Revision: 1.39 $");
  script_cvs_date("$Date: 2016/11/30 14:45:01 $");

  script_cve_id("CVE-2007-5269", "CVE-2007-5438", "CVE-2007-5503", "CVE-2008-1447", "CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808", "CVE-2008-2101", "CVE-2008-3691", "CVE-2008-3692", "CVE-2008-3693", "CVE-2008-3694", "CVE-2008-3695", "CVE-2008-3696", "CVE-2008-3697", "CVE-2008-3698", "CVE-2008-4194");
  script_bugtraq_id(25956, 26650, 29637, 29639, 29640, 29641, 30131);
  script_osvdb_id(38274, 39242, 43488, 46175, 46176, 46177, 46178, 46776, 48245, 48246, 48247, 48248, 48249, 48250, 48251, 48252, 48253, 48254);
  script_xref(name:"VMSA", value:"2008-0014");
  script_xref(name:"IAVA", value:"2008-A-0045");

  script_name(english:"VMSA-2008-0014 : Updates to VMware Workstation, VMware Player, VMware ACE, VMware Server, VMware ESX, VMware VCB address information disclosure, privilege escalation and other security issues.");
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
"I Security Issues

 a. Setting ActiveX kill bit

     Starting from this release, VMware has set the kill bit on its
     ActiveX controls. Setting the kill bit ensures that ActiveX
     controls cannot run in Internet Explorer (IE), and avoids
     security issues involving ActiveX controls in IE. See the
     Microsoft KB article 240797 and the related references on this
     topic.

     Security vulnerabilities have been reported for ActiveX controls
     provided by VMware when run in IE. Under specific circumstances,
     exploitation of these ActiveX controls might result in denial-of-
     service or can allow running of arbitrary code when the user
     browses a malicious Web site or opens a malicious file in IE
     browser. An attempt to run unsafe ActiveX controls in IE might
     result in pop-up windows warning the user.
  
     Note: IE can be configured to run unsafe ActiveX controls without
           prompting.  VMware recommends that you retain the default
           settings in IE, which prompts when unsafe actions are
           requested.

     Earlier, VMware had issued knowledge base articles, KB 5965318 and
     KB 9078920 on security issues with ActiveX controls. To avoid
     malicious scripts that exploit ActiveX controls, do not enable
     unsafe ActiveX objects in your browser settings. As a best
     practice, do not browse untrusted Web sites as an administrator
     and do not click OK or Yes if prompted by IE to allow certain
     actions.

     VMware would like to thank Julien Bachmann, Shennan Wang, Shinnai,
     and Michal Bucko for reporting these issues to us.

     The Common Vulnerabilities and Exposures Project (cve.mitre.org)
     has assigned the names CVE-2008-3691, CVE-2008-3692,
     CVE-2008-3693, CVE-2008-3694, CVE-2008-3695, CVE-2007-5438, and
     CVE-2008-3696 to the security issues with VMware ActiveX controls.

 b. VMware ISAPI Extension Denial of Service

     The Internet Server Application Programming Interface (ISAPI) is
     an API that extends the functionality of Internet Information
     Server (IIS). VMware uses ISAPI extensions in its Server product.

     One of the ISAPI extensions provided by VMware is vulnerable to a
     remote denial of service. By sending a malformed request, IIS
     might shut down. IIS 6.0 restarts automatically. However, IIS 5.0
     does not restart automatically when its Startup Type is set to
     Manual.

     VMware would like to thank the Juniper Networks J-Security
     Security Research Team for reporting this issue to us.

     The Common Vulnerabilities and Exposures Project (cve.mitre.org)
     has assigned the name CVE-2008-3697 to this issue.

 c. OpenProcess Local Privilege Escalation on Host System

     This release fixes a privilege escalation vulnerability in host
     systems.  Exploitation of this vulnerability allows users to run
     arbitrary code on the host system with elevated privileges.

     VMware would like to thank Sun Bing from McAfee, Inc. for
     reporting this issue to us.

     The Common Vulnerabilities and Exposures Project (cve.mitre.org)
     has assigned the name CVE-2008-3698 to this issue.

 d. Update to Freetype

     FreeType 2.3.6 resolves an integer overflow vulnerability and other
     vulnerabilities that can allow malicious users to run arbitrary code
     or might cause a denial-of-service after reading a maliciously
     crafted file. This release updates FreeType to 2.3.7.

     The Common Vulnerabilities and Exposures Project (cve.mitre.com)
     has assigned the names CVE-2008-1806, CVE-2008-1807, and
     CVE-2008-1808 to the issues resolved in Freetype 2.3.6.

 e. Update to Cairo

     Cairo 1.4.12 resolves an integer overflow vulnerability that can
     allow malicious users to run arbitrary code or might cause a
     denial-of-service after reading a maliciously crafted PNG file.
     This release updates Cairo to 1.4.14.

     The Common Vulnerabilities and Exposures (cve.mitre.com) has
     assigned the name CVE-2007-5503 to this issue.

  f. VMware Consolidated Backup (VCB) command-line utilities may expose
     sensitive information

     VMware Consolidated Backup command-line utilities accept the user
     password through the -p command-line option. Users logged into the
     ESX service console or into the system that runs VCB could gain
     access to the username and password used by VCB command-line
utilities
     when such commands are running.

     The ESX patch and the new version of VCB resolve this issue by
     providing an alternative way of passing the password used by VCB
     command-line utilities.

     VCB in ESX
     ----------
     The following options are recommended for passing the password :

     1. The password is specified in /etc/backuptools.conf
     (PASSWORD=xxxxx), and -p is not used in the command line.
     /etc/backuptools.conf file permissions are read/write only
     for root.

     2. No password is specified in /etc/backuptools.conf and the
     -p option is not used in the command line. The user will be
      prompted to enter a password.

     ESX is not affected unless you use VCB.

     Stand-alone VCB
     ---------------
     The following options are recommended for passing the password :

     1. The password is specified in config.js (PASSWORD=xxxxx), and -p
     is not used in the command line. The file permissions on config.js
     are read/write only for the administrator. The config.js file is
     located in folder 'config' of the VCB installation folder. For
example,
     C:\Program Files\Vmware\Vmware Consolidated Backup Framework\config.

     2. The password is specified in the registry, and is not specified in
     config.js, and -p is not used in the command line. Access to the
     registry key holding the password is allowed only to the
administrator.
     The location of the registry key is :
     On Windows x86: HKEY_LOCAL_MACHINE\SOFTWARE\VMware, Inc.\
                     VMware Consolidated Backup\Password
     On Windows x64: HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\
                     VMware, Inc.\VMware Consolidated Backup\Password

     3. The password is not specified in the registry, and is not
specified in
     config.js, and -p is not used in the command line. The user will be
     prompted to enter a password.

     The Common Vulnerabilities and Exposures project (cve.mitre.org)
     has assigned the name CVE-2008-2101 to this issue.

  g. Third-Party Library libpng Updated to 1.2.29

     Several flaws were discovered in the way third-party library
     libpng handled various PNG image chunks. An attacker could
     create a carefully crafted PNG image file in such a way that
     it causes an application linked with libpng to crash when the
     file is manipulated.

     The Common Vulnerabilities and Exposures project (cve.mitre.org)
     has assigned the name CVE-2007-5269 to this issue.

     NOTE: There are multiple patches required to remediate the issue.

II ESX Service Console rpm updates

  a. update to bind

     This update upgrades the service console rpms for bind-utils and
     bind-lib to version 9.2.4-22.el3.

     Version 9.2.4.-22.el3 addresses the recently discovered
     vulnerability in the BIND software used for Domain Name
     resolution (DNS). VMware doesn't install all the BIND packages
     on ESX Server and is not vulnerable by default to the reported
     vulnerability. Of the BIND packages, VMware only ships bind-util
     and bind-lib in the service console and these components by
     themselves cannot be used to setup a DNS server. Bind-lib and
     bind-util are used in client DNS applications like nsupdate,
     nslookup, etc.

     VMware explicitly discourages installing applications like BIND
     on the service console. In case the customer has installed BIND,
     and the DNS server is configured to support recursive queries,
     their ESX Server system is affected and they should replace BIND
     with a patched version.

     Note: ESX Server will use the DNS server on the network it is
     on, so it is important to patch that DNS server.

     The Common Vulnerabilities and Exposures project (cve.mitre.org)
     has assigned the name CVE-2008-1447 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2008/000040.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 189, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.5.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:3.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/05");
  script_set_attribute(attribute:"stig_severity", value:"I");
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


init_esx_check(date:"2008-08-29");
flag = 0;


if (esx_check(ver:"ESX 2.5.4", patch:"20")) flag++;

if (esx_check(ver:"ESX 2.5.5", patch:"10")) flag++;

if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1004823")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1005108")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1005111")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1005112")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1005117")) flag++;

if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1005109")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1005113")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1005114")) flag++;

if (
  esx_check(
    ver           : "ESX 3.0.3",
    patch         : "ESX303-200808403-SG",
    patch_updates : make_list("ESX303-201002201-UG", "ESX303-Update01")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.0.3",
    patch         : "ESX303-200808404-SG",
    patch_updates : make_list("ESX303-201002201-UG", "ESX303-Update01")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.0.3",
    patch         : "ESX303-200808406-SG",
    patch_updates : make_list("ESX303-201002205-UG", "ESX303-Update01")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200808409-SG",
    patch_updates : make_list("ESX350-201002404-SG", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;

if (esx_check(ver:"ESXi 3.5.0", patch:"ESXe350-200808501-I-SG")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
