#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2009-0005. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(40390);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id("CVE-2008-3761", "CVE-2008-4916", "CVE-2009-0177", "CVE-2009-0518", "CVE-2009-0908", "CVE-2009-0909", "CVE-2009-0910", "CVE-2009-1146", "CVE-2009-1147");
  script_bugtraq_id(30737, 34373);
  script_osvdb_id(48051, 51180, 53409, 53694, 53695, 53696, 55942, 55943, 56409);
  script_xref(name:"VMSA", value:"2009-0005");

  script_name(english:"VMSA-2009-0005 : VMware Hosted products, VI Client and patches for ESX and ESXi resolve multiple security issues");
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
"a. Denial of service guest to host vulnerability in a virtual device

   A vulnerability in a guest virtual device driver, could allow a
   guest operating system to crash the host and consequently any
   virtual machines on that host.

   VMware would like to thank Andrew Honig of the Department of
   Defense for reporting this issue.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2008-4916 to this issue.

b. Windows-based host denial of service vulnerability in hcmon.sys

   A vulnerability in an ioctl in hcmon.sys could be used to create
   a denial of service on a Windows-based host. This issue can only
   be exploited by a privileged Windows account.

   VMware would like to thank Nikita Tarakanov for reporting this
   issue to us.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2009-1146 to this issue.

   Note: newly released hosted products (see table in this section)
   address another potential denial of service in hcmon.sys as well.
   Also this issue can only be exploited by a privileged Windows
   account.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2008-3761 to this issue.

c. A VMCI privilege escalation on Windows-based hosts or Windows-
   based guests.

   The Virtual Machine Communication Interface (VMCI) is an
   infrastructure that provides fast and efficient communication
   between a virtual machine and the host operating system and
   between two or more virtual machines on the same host.

   A vulnerability in vmci.sys could allow privilege escalation on
   Windows-based machines. This could occur on Windows-based hosts or
   inside Windows-based guest operating systems.  

   Current versions of ESX do not support the VMCI interface and
   hence they are not affected by this vulnerability.
  
   Note: Installing the new hosted releases will not remediate the
   issue on Windows-based guests. The VMware Tools packages will need
   to be updated on each Windows-based guest followed by a reboot
   of the guest system.

   VMware would like to thank Nikita Tarakanov for reporting this
   issue to us.

   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the name CVE-2009-1147 to this issue.

   Refer to VMware KB article 1009826 on the steps that are needed to
   remediate this vulnerability on Windows-based hosts. This KB article
   is found at http://kb.vmware.com/kb/1009826.

d. VNnc Codec Heap Overflow vulnerabilities

   The VNnc Codec assists in Record and Replay sessions. Record and
   Replay record the dynamic virtual machine state over a period of
   time.

   Two heap overflow vulnerabilities could allow a remote attacker to
   execute arbitrary code on VMware hosted products. For an attack to
   be successful the user must be tricked into visiting a malicious web
   page or opening a malicious video file.

   VMware would like to thank Aaron Portnoy from TippingPoint DVLabs
   for reporting these issues to us. TippingPoint has issued the
   following identifiers: ZDI-CAN-435, ZDI-CAN-436.

   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   has assigned the names CVE-2009-0909 and CVE-2009-0910 to these
   issues.

e. ACE shared folders vulnerability

   The VMware Host Guest File System (HGFS) shared folders feature allows
   users to transfer data between a guest operating system and the
   non-virtualized host operating system that contains it.

   A vulnerability in ACE shared folders could allow a previously disabled
   and not removed shared folder in the guest to be enabled by a non ACE
   Administrator.
     
   VMware would like to thank Emmanouel Kellinis, KPMG London, penetration
   testing team for reporting this issue to us.

   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   has assigned the name CVE-2009-0908 to this issue.

f. A remote denial of service vulnerability in authd for Windows
   based hosts.

   A vulnerability in vmware-authd.exe could cause a denial
   of service condition on Windows hosts.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-0177 to this issue.

g. VI Client Retains VirtualCenter Server Password in Memory

   After logging in to VirtualCenter Server with VI Client, the
   password for VirtualCenter Server might be present in the memory
   of the VI Client.

   Note: This vulnerability is present in VI Client and in order to
   remediate the vulnerability, you will need to replace VI Client
   with a fixed version (see below).

   VMware would like to thank Craig Marshall for reporting this
   issue to us.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-0518 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2009/000054.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:3.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/27");
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


init_esx_check(date:"2009-04-03");
flag = 0;


if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1006980")) flag++;

if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200811401-SG",
    patch_updates : make_list("ESX350-200911201-UG", "ESX350-201006401-SG", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200903201-UG",
    patch_updates : make_list("ESX350-200911201-UG", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;

if (esx_check(ver:"ESXi 3.5.0", patch:"ESXe350-200811401-O-SG")) flag++;
if (esx_check(ver:"ESXi 3.5.0", patch:"ESXe350-200903201-O-UG")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
