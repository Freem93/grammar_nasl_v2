#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2007-0006. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(40370);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2017/04/18 13:37:18 $");

  script_cve_id("CVE-2004-0813", "CVE-2006-1174", "CVE-2006-3619", "CVE-2006-4146", "CVE-2006-4600", "CVE-2007-0061", "CVE-2007-0062", "CVE-2007-0063", "CVE-2007-0494", "CVE-2007-1716", "CVE-2007-1856", "CVE-2007-2442", "CVE-2007-2443", "CVE-2007-2446", "CVE-2007-2447", "CVE-2007-2798", "CVE-2007-4059", "CVE-2007-4155", "CVE-2007-4496", "CVE-2007-4497");
  script_bugtraq_id(18111, 19832, 22231, 23520, 23972, 23973, 24195, 24196, 24197, 24198, 24653, 24655, 24657, 25110, 25131, 25729, 25731, 25732);
  script_osvdb_id(10352, 25848, 27380, 28318, 28464, 31923, 34699, 34700, 34731, 34732, 34733, 34975, 36595, 36596, 36597, 37271, 40093, 40094, 40095, 40096, 40099, 40100);
  script_xref(name:"VMSA", value:"2007-0006");

  script_name(english:"VMSA-2007-0006 : Critical security updates for all supported versions of VMware ESX Server, VMware Server, VMware Workstation, VMware ACE, and VMware Player");
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
"Problems addressed by these patches :

I    Arbitrary code execution and denial of service vulnerabilities

     This release fixes a security vulnerability that could allow a
     guest operating system user with administrative privileges to cause
     memory corruption in a host process, and thus potentially execute
     arbitrary code on the host. (CVE-2007-4496)

     This release fixes a denial of service vulnerability that could
     allow a guest operating system to cause a host process to become
     unresponsive or exit unexpectedly. (CVE-2007-4497)

     Thanks to Rafal Wojtczvk of McAfee for identifying and reporting
     these issues.

II   Hosted products DHCP security vulnerabilities addressed

     This release fixes several vulnerabilities in the DHCP server
     that could enable a specially crafted packets to gain system-level
     privileges. (CVE-2007-0061, CVE-2007-0062, CVE-2007-0063)

     Thanks to Neel Mehta and Ryan Smith of the IBM Internet Security
     Systems X-Force for discovering and researching these
     vulnerabilities.

III  Windows based hosted product vulnerability in
     IntraProcessLogging.dll and vielib.dll.

     This release fixes a security vulnerability that could allow a
     malicious remote user to exploit the library file
     IntraProcessLogging.dll to overwrite files in a system.
     (CVE-2007-4059)

     This release fixes a security vulnerability that could allow a
     malicious remote user to exploit the library file vielib.dll to
     overwrite files in a system. (CVE-2007-4155)

     Thanks to the Goodfellas Security Research Team for discovering and
     researching these vulnerabilities.

IV  Escalation of privileges on Windows hosted systems

     This release fixes a security vulnerability in which Workstation
     was starting registered Windows services in an insecure manner.
     This vulnerability could allow a malicious user to escalate user
     privileges.

     Thanks to Foundstone for discovering this vulnerability.

V    Potential denial of service using VMware Player

     This release fixes a problem that prevented VMware Player from
     launching. This problem was accompanied by the error message VMware
     Player unrecoverable error: (player) Exception 0xc0000005 (access
     violation) has occurred.

VI   ESX Service Console updates

a.   Service console package Samba, has been updated to address the
     following issues :

     Various bugs were found in NDR parsing, used to decode MS-RPC
     requests in Samba. A remote attacker could have sent carefully
     crafted requests causing a heap overflow, which may have led to the
     ability to execute arbitrary code on the server. (CVE-2007-2446)

     Unescaped user input parameters were being passed as arguments to
     /bin/sh. A remote, authenticated, user could have triggered this
     flaw and executed arbitrary code on the server. Additionally, this
     flaw could be triggered by a remote unauthenticated user if Samba
     was configured to use the non-default username map script option.
     (CVE-2007-2447)

     Thanks to the Samba developers, TippingPoint, and iDefense for
     identifying and reporting these issues.

     Note: These issues only affect the service console network, and are
     not remote vulnerabilities for ESX Server hosts that have been set
     up with the security best practices provided by VMware.
     http://www.vmware.com/resources/techresources/726

b.   Updated bind package for the service console fixes a flaw with the
     way ISC BIND processed certain DNS query responses.

     ISC BIND (Berkeley Internet Name Domain) is an implementation of
     the DNS (Domain Name System) protocols. Under some circumstances, a
     malicious remote user could launch a Denial-of-Service attack on
     ESX Server hosts that had enabled DNSSEC validation.
     (CVE-2007-0494)

     Note: These issues only affect the service console network, and are
     not remote vulnerabilities for ESX Server hosts that have been set
     up with the security best practices provided by VMware.
     http://www.vmware.com/resources/techresources/726

c.   This patch provides updated service console package krb5 update.

     The Common Vulnerabilities and Exposures project (cve.mitre.org)
     assigned the names CVE-2007-2442, CVE-2007-2443, and CVE-2007-2798
     to these security issues.

     Thanks to Wei Wang of McAfee Avert Labs discovered these
     vulnerabilities.

     Note: The VMware service console does not provide the kadmind
     binary, and is not affected by these issues, but a update has been
     provided for completeness.

d.   Service console update for vixie-cron

     This patch provides an updated service console package vixie-cron.
     Cron is a standard UNIX daemon that runs specified programs at
     scheduled times.

     A denial of service issue was found in the way vixie-cron verified
     crontab file integrity. A local user with the ability to create a
     hardlink to /etc/crontab could potentially prevent vixie-cron from
     executing certain system cron jobs. (CVE-2007-1856)

     Thanks to Raphael Marichez for identifying this issue.

e.   Service console update for shadow-utils

     This patch provides an updated shadow-utils package.  A new
     user's mailbox, when created, could have random permissions for a
     short period. This could enable a local malicious user to
     read or modify the mailbox. (CVE-2006-1174)

f.  Service console update for OpenLDAP

     This patch provides a updated OpenLDAP package. A flaw could
     allow users with selfwrite access to modify the distinguished
     name of any user, instead of being limited to modify only
     their own distinguished name. (CVE-2006-4600)

g.   Service console update for PAM

     This patch provides an updated PAM package A vulnerability was
     found that could allow console users with access to certain device
     files to cause damage to recordable CD drives. Certain file
     permissions have now been modified to disallow access.
     (CVE-2004-0813)

     A flaw was found with console device permissions. It was possible
     for various console devices to retain ownership of the previoius
     console user after logging out, which could result in leakage of
     information to an unauthorized user. (CVE-2007-1716)

h.   Service console update for GCC

     This patch provides security fixes for the service console GNU
     Compiler Collection (GCC) packages that include C, C++, Java,
     Fortran 77, Objective C, and Ada 95 GNU compilers and related
     support libraries.

     A flaw was found in the fastjar utility that could potentially
     allow a malicious user to create a JAR file which, if unpacked
     using fastjar, could write to any file that an authorized user had
     write access to. (CVE-2006-3619)

     Thanks to J&uuml;rgen Weigert for identifying this issue.

i.   Service Console update for GDB

     This patch provides a security fix for the service console GNU
     debugger (GDB).  Various vulnerabilities were found in GDB. These
     vulnerabilities may allow a malicious user to deceive a user into
     loading debugging information into GDB, enabling the execution of
     arbitrary code with the privileges of the user. (CVE-2006-4146)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2007/000001.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba "username map script" Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.0.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.1.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.5.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.5.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");
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


init_esx_check(date:"2007-09-18");
flag = 0;


if (esx_check(ver:"ESX 2.0.2", patch:"8")) flag++;

if (esx_check(ver:"ESX 2.1.3", patch:"8")) flag++;

if (esx_check(ver:"ESX 2.5.3", patch:"13")) flag++;

if (esx_check(ver:"ESX 2.5.4", patch:"10")) flag++;

if (esx_check(ver:"ESX 3.0.0", patch:"ESX-1001204")) flag++;
if (esx_check(ver:"ESX 3.0.0", patch:"ESX-1001205")) flag++;
if (esx_check(ver:"ESX 3.0.0", patch:"ESX-1001206")) flag++;
if (esx_check(ver:"ESX 3.0.0", patch:"ESX-1001207")) flag++;
if (esx_check(ver:"ESX 3.0.0", patch:"ESX-1001208")) flag++;
if (esx_check(ver:"ESX 3.0.0", patch:"ESX-1001209")) flag++;
if (esx_check(ver:"ESX 3.0.0", patch:"ESX-1001210")) flag++;
if (esx_check(ver:"ESX 3.0.0", patch:"ESX-1001211")) flag++;
if (esx_check(ver:"ESX 3.0.0", patch:"ESX-1001212")) flag++;
if (esx_check(ver:"ESX 3.0.0", patch:"ESX-4809553")) flag++;

if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1001213")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1001214")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1001691")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1001692")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1001693")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1001694")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1001723")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-8253547")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-8258730")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-8567382")) flag++;

if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1001725")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1001726")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1001727")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1001728")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1001729")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1001730")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1001731")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
