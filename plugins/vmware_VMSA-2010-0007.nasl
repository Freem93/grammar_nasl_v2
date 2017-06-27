#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2010-0007. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(56246);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/30 14:45:01 $");

  script_cve_id("CVE-2009-1564", "CVE-2009-1565", "CVE-2009-2042", "CVE-2009-3707", "CVE-2009-3732", "CVE-2009-4811", "CVE-2010-1138", "CVE-2010-1139", "CVE-2010-1140", "CVE-2010-1141", "CVE-2010-1142");
  script_bugtraq_id(35233, 36630, 39395, 39396);
  script_osvdb_id(54915, 58728, 63605, 63606, 63607, 63614, 63615, 63858, 63859, 63860, 64127);
  script_xref(name:"VMSA", value:"2010-0007");
  script_xref(name:"IAVA", value:"2010-A-0066");

  script_name(english:"VMSA-2010-0007 : VMware hosted products, vCenter Server and ESX patches resolve multiple security issues");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. Windows-based VMware Tools Unsafe Library Loading vulnerability

   A vulnerability in the way VMware libraries are referenced allows
   for arbitrary code execution in the context of the logged on user.
   This vulnerability is present only on Windows Guest Operating
   Systems.

   In order for an attacker to exploit the vulnerability, the attacker
   would need to lure the user that is logged on a Windows Guest
   Operating System to click on the attacker's file on a network
   share. This file could be in any file format. The attacker will
   need to have the ability to host their malicious files on a
   network share.

   VMware would like to thank Jure Skofic and Mitja Kolsek of ACROS
   Security (http://www.acrossecurity.com) for reporting this issue
   to us.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2010-1141 to this issue.

   Steps needed to remediate this vulnerability :

   Guest systems on VMware Workstation, Player, ACE, Server, Fusion
    - Install the remediated version of Workstation, Player, ACE,
      Server and Fusion.
    - Upgrade tools in the virtual machine (virtual machine users
      will be prompted to upgrade).

   Guest systems on ESX 4.0, 3.5, 3.0.3, 2.5.5, ESXi 4.0, 3.5
    - Install the relevant patches (see below for patch identifiers)
    - Manually upgrade tools in the virtual machine (virtual machine
      users will not be prompted to upgrade).  Note the VI Client will
      not show the VMware tools is out of date in the summary tab.
      Please see http://tinyurl.com/27mpjo page 80 for details.

b. Windows-based VMware Tools Arbitrary Code Execution vulnerability

   A vulnerability in the way VMware executables are loaded allows for
   arbitrary code execution in the context of the logged on user. This
   vulnerability is present only on Windows Guest Operating Systems.

   In order for an attacker to exploit the vulnerability, the attacker
   would need to be able to plant their malicious executable in a
   certain location on the Virtual Machine of the user.  On most
   recent versions of Windows (XP, Vista) the attacker would need to
   have administrator privileges to plant the malicious executable in
   the right location.

   Steps needed to remediate this vulnerability: See section 3.a.

   VMware would like to thank Mitja Kolsek of ACROS Security
   (http://www.acrossecurity.com) for reporting this issue to us.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2010-1142 to this issue.

   Refer to the previous table in section 3.a for what action
   remediates the vulnerability (column 4) if a solution is
   available. See above for remediation details.

c. Windows-based VMware Workstation and Player host privilege
   escalation

   A vulnerability in the USB service allows for a privilege
   escalation. A local attacker on the host of a Windows-based
   Operating System where VMware Workstation or VMware Player
   is installed could plant a malicious executable on the host and
   elevate their privileges.

   In order for an attacker to exploit the vulnerability, the attacker
   would need to be able to plant their malicious executable in a
   certain location on the host machine.  On most recent versions of
   Windows (XP, Vista) the attacker would need to have administrator
   privileges to plant the malicious executable in the right location.

   VMware would like to thank Thierry Zoller for reporting this issue
   to us.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2010-1140 to this issue.

d. Third-party library update for libpng to version 1.2.37

   The libpng libraries through 1.2.35 contain an uninitialized-
   memory-read bug that may have security implications.
   Specifically, 1-bit (2-color) interlaced images whose widths are
   not divisible by 8 may result in several uninitialized bits at the
   end of certain rows in certain interlace passes being returned to
   the user. An application that failed to mask these out-of-bounds
   pixels might display or process them, albeit presumably with benign
   results in most cases.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-2042 to this issue.

e. VMware VMnc Codec heap overflow vulnerabilities

   The VMware movie decoder contains the VMnc media codec that is
   required to play back movies recorded with VMware Workstation,
   VMware Player and VMware ACE, in any compatible media player. The
   movie decoder is installed as part of VMware Workstation, VMware
   Player and VMware ACE, or can be downloaded as a stand alone
   package.

   Vulnerabilities in the decoder allow for execution of arbitrary
   code with the privileges of the user running an application
   utilizing the vulnerable codec.

   For an attack to be successful the user must be tricked into
   visiting a malicious web page or opening a malicious video file on
   a system that has the vulnerable version of the VMnc codec installed.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2009-1564 and CVE-2009-1565 to these
   issues.

   VMware would like to thank iDefense, Sebastien Renaud of VUPEN
   Vulnerability Research Team (http://www.vupen.com) and Alin Rad Pop
   of Secunia Research for reporting these issues to us.

   To remediate the above issues either install the stand alone movie
   decoder or update your product using the table below.

f. VMware Remote Console format string vulnerability

   VMware Remote Console (VMrc) contains a format string vulnerability.
   Exploitation of this issue may lead to arbitrary code execution on
   the system where VMrc is installed.

   For an attack to be successful, an attacker would need to trick the
   VMrc user into opening a malicious Web page or following a malicious
   URL. Code execution would be at the privilege level of the user.

   VMrc is present on a system if the VMrc browser plug-in has been
   installed. This plug-in is required when using the console feature in
   WebAccess. Installation of the plug-in follows after visiting the
   console tab in WebAccess and choosing 'Install plug-in'. The plug-
   in can only be installed on Internet Explorer and Firefox.

   Under the following two conditions your version of VMrc is likely
   to be affected :

   - the VMrc plug-in was obtained from vCenter 4.0 or from ESX 4.0
     without patch ESX400-200911223-UG and
   - VMrc is installed on a Windows-based system

   The following steps allow you to determine if you have an affected
   version of VMrc installed :

   - Locate the VMrc executable vmware-vmrc.exe on your Windows-based
     system
   - Right click and go to Properties
   - Go to the tab 'Versions'
   - Click 'File Version' in the 'Item Name' window
   - If the 'Value' window shows 'e.x.p build-158248', the version of
     VMrc is affected

   Remediation of this issue on Windows-based systems requires the
   following steps (Linux-based systems are not affected) :

   - Uninstall affected versions of VMrc from the systems where the
     VMrc plug-in has been installed (use the Windows Add/Remove
     Programs interface)
   - Install vCenter 4.0 Update 1 or install the ESX 4.0 patch
     ESX400-200911223-UG
   - Login into vCenter 4.0 Update 1 or ESX 4.0 with patch
     ESX400-200911223-UG using WebAccess on the system where the VMrc
     needs to be re-installed
   - Re-install VMrc by going to the console tab in WebAccess.  The
     Console tab is selectable after selecting a virtual machine.

   Note: the VMrc plug-in for Firefox on Windows-based operating
   systems is no longer compatible after the above remediation steps.
   Users are advised to use the Internet Explorer VMrc plug-in.

   VMware would like to thank Alexey Sintsov from Digital Security
   Research Group for reporting this issue to us.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2009-3732 to this issue.


g. Windows-based VMware authd remote denial of service

   A vulnerability in vmware-authd could cause a denial of service
   condition on Windows-based hosts.  The denial of service is limited
   to a crash of authd.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-3707 to this issue.

h. Potential information leak via hosted networking stack

   A vulnerability in the virtual networking stack of VMware hosted
   products could allow host information disclosure.

   A guest operating system could send memory from the host vmware-vmx
   process to the virtual network adapter and potentially to the
   host's physical Ethernet wire.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2010-1138 to this issue.

   VMware would like to thank Johann MacDonagh for reporting this
   issue to us.

i. Linux-based vmrun format string vulnerability

   A format string vulnerability in vmrun could allow arbitrary code
   execution.

   If a vmrun command is issued and processes are listed, code could
   be executed in the context of the user listing the processes.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2010-1139 to this issue.

   VMware would like to thank Thomas Toth-Steiner for reporting this
   issue to us."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2010/000091.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(134, 200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/21");
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


init_esx_check(date:"2010-04-09");
flag = 0;


if (esx_check(ver:"ESX 2.5.5", patch:"15")) flag++;

if (esx_check(ver:"ESX 3.0.3", patch:"ESX303-201002203-UG")) flag++;

if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-200911223-UG",
    patch_updates : make_list("ESX400-Update01a", "ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
