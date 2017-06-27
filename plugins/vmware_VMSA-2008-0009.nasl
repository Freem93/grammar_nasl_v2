#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2008-0009. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(40378);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id("CVE-2006-1721", "CVE-2007-4772", "CVE-2007-5137", "CVE-2007-5378", "CVE-2007-5671", "CVE-2008-0062", "CVE-2008-0063", "CVE-2008-0553", "CVE-2008-0888", "CVE-2008-0948", "CVE-2008-0967", "CVE-2008-2097", "CVE-2008-2100");
  script_bugtraq_id(27163, 27655, 28288, 28302, 28303, 29557);
  script_osvdb_id(24510, 40905, 41264, 43332, 43341, 43342, 43344, 46089, 46203, 46204, 46205);
  script_xref(name:"VMSA", value:"2008-0009");

  script_name(english:"VMSA-2008-0009 : Updates to VMware Workstation, VMware Player, VMware ACE, VMware Fusion, VMware Server, VMware VIX API, VMware ESX, VMware ESXi resolve critical security issues");
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
"a. VMware Tools Local Privilege Escalation on Windows-based guest OS

   The VMware Tools Package provides support required for shared folders
   (HGFS) and other features.

   An input validation error is present in the Windows-based VMware
   HGFS.sys driver.   Exploitation of this flaw might result in
   arbitrary code execution on the guest system by an unprivileged
   guest user.  It doesn't matter on what host the Windows guest OS
   is running, as this is a guest driver vulnerability and not a
   vulnerability on the host.

   The HGFS.sys driver is present in the guest operating system if the
   VMware Tools package is loaded.  Even if the host has HGFS disabled
   and has no shared folders, Windows-based guests may be affected. This
   is regardless if a host supports HGFS.

   This issue could be mitigated by removing the VMware Tools package
   from Windows based guests.  However this is not recommended as it
   would impact usability of the product.

   NOTE: Installing the new hosted release or ESX patches will not
         remediate the issue.  The VMware Tools packages will need
         to be updated on each Windows-based guest followed by a
         reboot of the guest system.

   VMware would like to thank iDefense and Stephen Fewer of Harmony
   Security for reporting this issue to us.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2007-5671 to this issue.

b. Privilege escalation on ESX or Linux based hosted operating systems

   This update fixes a security issue related to local exploitation of
   an untrusted library path vulnerability in vmware-authd. In order to
   exploit this vulnerability, an attacker must have local access and
   the ability to execute the set-uid vmware-authd binary on an affected
   system. Exploitation of this flaw might result in arbitrary code
   execution on the Linux host system by an unprivileged user.

   VMware would like to thank iDefense for reporting this issue to us.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2008-0967 to this issue.

c. Openwsman Invalid Content-Length Vulnerability

   Openwsman is a system management platform that implements the Web
   Services Management protocol (WS-Management). It is installed and
   running by default. It is used in the VMware Management Service
   Console and in ESXi.

   The openwsman management service on ESX 3.5 and ESXi 3.5 is vulnerable
   to a privilege escalation vulnerability, which may allow users with
   non-privileged ESX or Virtual Center accounts to gain root privileges.

   To exploit this vulnerability, an attacker would need a local ESX
   account or a VirtualCenter account with the Host.Cim.CimInteraction
   permission.

   Systems with no local ESX accounts and no VirtualCenter accounts with
   the Host.Cim.CimInteraction permission are not vulnerable.

   This vulnerability cannot be exploited by users without valid login
   credentials.

   Discovery: Alexander Sotirov, VMware Security Research

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2008-2097 to this issue.

d. VMware VIX Application Programming Interface (API) Memory Overflow
   Vulnerabilities

   The VIX API (also known as 'Vix') is an API that lets users write scripts
   and programs to manipulate virtual machines.

   Multiple buffer overflow vulnerabilities are present in the VIX API.
   Exploitation of these vulnerabilities might result in a privilege
   escalation on the host system. This exploit scenario is relevant for all
   affected products. On VC, ESX30x, and ESX35, users need to have the VM
   Interaction Privilege in order to exploit the vulnerability.

   Exploitation of these vulnerabilities might also result in code execution on
   the host system from the guest system or on the service console in ESX Server
   from the guest operating system. This exploit scenario is relevant for
   Workstation 6.0.x (version 6.0.3 and below), Player 2.0.x (version 2.0.3 and
   below), ACE 2.0.x (version 2.0.3 and below), Server 1.0.x (version 1.0.5 and
   below), and ESX3.5. The parameter 'vix.inGuest.enable' in the VMware
   configuration file must be set to true to allow for exploitation on these
   products. Note that the parameter 'vix-inGuest.enable' is set to false by
   default.

   The parameter 'vix.inGuest.enable' is present in the
   following products :

     VMware Workstation 6.0.2 and higher
     VMware ACE 6.0.2 and higher
     VMware Server 1.06 and higher
     VMware Fusion 1.1.2 and higher
     ESX Server 3.0 and higher
     ESX Server 3.5 and higher

   In previous versions of VMware products where the VIX API was introduced,
   the VIX API couldn't be disabled.

   This vulnerability is present in ESX and the hosted products even if you
   have not installed the VIX API. To patch your system you will need to
   update to the new hosted product version or to apply the appropriate ESX
   patch. It is not necessary to update the VIX API if you have installed
   the VIX API.

   VMware would like to thank Andrew Honig of the Department of
   Defense for reporting this issue.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2008-2100 to this issue.

II Service Console rpm updates

 NOTE: ESXi and hosted products are not affected by any service console
       security updates

 a. Security update for cyrus-sasl

   Updated cyrus-sasl package for the ESX Service Console corrects a security
   issue found in the DIGEST-MD5 authentication mechanism of Cyrus'
   implementation of Simple Authentication and Security Layer (SASL). As a
   result of this issue in the authentication mechanism, a remote
   unauthenticated attacker might be able to cause a denial of service error
   on the service console.

   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the name CVE-2006-1721 to this issue.

 b. Security update for tcltk

   An input validation flaw was discovered in Tk's GIF image handling. A
   code-size value read from a GIF image was not properly validated before
   being used, leading to a buffer overflow. A specially crafted GIF file
   could use this to cause a crash or, potentially, execute code with the
   privileges of the application using the Tk graphical toolkit.

   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the name CVE-2008-0553 to this issue.

   A buffer overflow flaw was discovered in Tk's animated GIF image handling.
   An animated GIF containing an initial image smaller than subsequent images
   could cause a crash or, potentially, execute code with the privileges of
   the application using the Tk library.

   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the name CVE-2007-5378 to this issue.

   A flaw first discovered in the Tcl regular expression engine used in the
   PostgreSQL database server, resulted in an infinite loop when processing
   certain regular expressions.

   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the name CVE-2007-4772 to this issue.

 c. Security update for unzip

   This patch includes a moderate security update to the service console that
   fixes a flaw in unzip. An attacker could execute malicious code with a
   user's privileges if the user ran unzip on a file designed to leverage
   this flaw.

   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the name CVE-2008-0888 to this issue.

 d. Security update for krb5

   KDC in MIT Kerberos 5 (krb5kdc) does not set a global variable
   for some krb4 message types, which allows remote attackers to
   cause a denial of service (crash) and possibly execute arbitrary
   code via crafted messages that trigger a NULL pointer dereference
   or double-free.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2008-0062 to this issue.

   NOTE: ESX doesn't contain the krb5kdc binary and is not vulnerable
         to this issue.

   The Kerberos 4 support in KDC in MIT Kerberos 5 (krb5kdc) does not
   properly clear the unused portion of a buffer when generating an
   error message, which might allow remote attackers to obtain
   sensitive information, aka 'Uninitialized stack values.'

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2008-0063 to this issue.

   NOTE: ESX doesn't contain the krb5kdc binary and is not vulnerable
         to this issue.

   Buffer overflow in the RPC library (lib/rpc/rpc_dtablesize.c) used
   by libgssrpc and kadmind in MIT Kerberos 5 (krb5) 1.2.2, and probably
   other versions before 1.3, when running on systems whose unistd.h
   does not define the FD_SETSIZE macro, allows remote attackers to cause
   a denial of service (crash) and possibly execute arbitrary code by
   triggering a large number of open file descriptors.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2008-0948 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2008/000022.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.5.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:3.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/07");
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


init_esx_check(date:"2008-06-04");
flag = 0;


if (esx_check(ver:"ESX 2.5.4", patch:"19")) flag++;

if (esx_check(ver:"ESX 2.5.5", patch:"8")) flag++;

if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1004186")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1004189")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1004190")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1004721")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1004723")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1004725")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1004728")) flag++;

if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1004216")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1004219")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1004719")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1004722")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1004724")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1004726")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1004727")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1004821")) flag++;

if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200805504-SG",
    patch_updates : make_list("ESX350-Update02", "ESX350-Update03", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200805505-SG",
    patch_updates : make_list("ESX350-Update02", "ESX350-Update03", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200805506-SG",
    patch_updates : make_list("ESX350-Update02", "ESX350-Update03", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200805507-SG",
    patch_updates : make_list("ESX350-201006408-SG", "ESX350-201008411-SG", "ESX350-Update02", "ESX350-Update03", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200805508-SG",
    patch_updates : make_list("ESX350-200911210-UG", "ESX350-200912406-BG", "ESX350-201006409-BG", "ESX350-201105403-BG", "ESX350-Update02", "ESX350-Update03", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200805515-SG",
    patch_updates : make_list("ESX350-200911201-UG", "ESX350-201006401-SG", "ESX350-201203401-SG", "ESX350-Update02", "ESX350-Update03", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;

if (esx_check(ver:"ESXi 3.5.0", patch:"ESXe350-200805501-I-SG")) flag++;
if (esx_check(ver:"ESXi 3.5.0", patch:"ESXe350-200805502-T-SG")) flag++;
if (esx_check(ver:"ESXi 3.5.0", patch:"ESXe350-200805503-C-SG")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
