#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2010-0018. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(50985);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2010-4294", "CVE-2010-4295", "CVE-2010-4296", "CVE-2010-4297");
  script_bugtraq_id(45167, 45168);
  script_osvdb_id(69584, 69585, 69590, 69596);
  script_xref(name:"VMSA", value:"2010-0018");
  script_xref(name:"IAVA", value:"2010-A-0168");

  script_name(english:"VMSA-2010-0018 : VMware hosted products and ESX patches resolve multiple security issues");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. VMware Workstation, Player and Fusion vmware-mount race condition

   The way temporary files are handled by the mounting process could
   result in a race condition. This issue could allow a local user on
   the host to elevate their privileges.

   VMware Workstation and Player running on Microsoft Windows are not
   affected.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2010-4295 to this issue.

   VMware would like to thank Dan Rosenberg for reporting this issue.

b. VMware Workstation, Player and Fusion vmware-mount privilege
   escalation

   vmware-mount which is a suid binary has a flaw in the way libraries
   are loaded.  This issue could allow local users on the host to
   execute arbitrary shared object files with root privileges.

   VMware Workstation and Player running on Microsoft Windows are not
   affected.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2010-4296 to this issue.

   VMware would like to thank Martin Carpenter for reporting this
   issue.

c. OS Command Injection in VMware Tools update

   A vulnerability in the input validation of VMware Tools update
   allows for injection of commands. The issue could allow a  user
   on the host to execute commands on the guest operating system
   with root privileges.

   The issue can only be exploited if VMware Tools is not fully
   up-to-date.  Windows-based virtual machines are not affected.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2010-4297 to this issue.

   VMware would like to thank Nahuel Grisolia of Bonsai Information
   Security, http://www.bonsai-sec.com, for reporting this issue.

d. VMware VMnc Codec frame decompression remote code execution

   The VMware movie decoder contains the VMnc media codec that is
   required to play back movies recorded with VMware Workstation,
   VMware Player and VMware ACE, in any compatible media player. The
   movie decoder is installed as part of VMware Workstation, VMware
   Player and VMware ACE, or can be downloaded as a stand alone
   package.

   A function in the decoder frame decompression routine implicitly
   trusts a size value.  An attacker can utilize this to miscalculate
   a destination pointer, leading to the corruption of a heap buffer,
   and could allow for execution of arbitrary code with the privileges
   of the user running an application utilizing the vulnerable codec.

   For an attack to be successful the user must be tricked into
   visiting a malicious web page or opening a malicious video file on
   a system that has the vulnerable version of the VMnc codec installed.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2010-4294 to this issue.

   VMware would like to thank Aaron Portnoy and Logan Brown of
   TippingPoint DVLabs for reporting this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2010/000112.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/06");
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


init_esx_check(date:"2010-12-02");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201009401-SG",
    patch_updates : make_list("ESX400-201101401-SG", "ESX400-201103401-SG", "ESX400-201104401-SG", "ESX400-201110401-SG", "ESX400-201111201-SG", "ESX400-201203401-SG", "ESX400-201205401-SG", "ESX400-201206401-SG", "ESX400-201209401-SG", "ESX400-201302401-SG", "ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
