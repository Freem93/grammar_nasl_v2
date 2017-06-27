#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2011-0009. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(54968);
  script_version("$Revision: 1.40 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2009-3080", "CVE-2009-4536", "CVE-2010-1188", "CVE-2010-2240", "CVE-2011-1787", "CVE-2011-2145", "CVE-2011-2146", "CVE-2011-2217");
  script_bugtraq_id(37068, 37519, 39016, 42505, 48098, 48099);
  script_osvdb_id(60311, 61769, 63453, 67237, 73211, 73240, 73241, 73242);
  script_xref(name:"VMSA", value:"2011-0009");
  script_xref(name:"IAVA", value:"2011-A-0075");

  script_name(english:"VMSA-2011-0009 : VMware hosted product updates, ESX patches and VI Client update resolve multiple security issues");
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
"a. VMware vmkernel third-party e1000(e) Driver Packet Filter Bypass

    There is an issue in the e1000(e) Linux driver for Intel PRO/1000
    adapters that allows a remote attacker to bypass packet filters.

    The Common Vulnerabilities and Exposures project (cve.mitre.org)
    has assigned the name CVE-2009-4536 to this issue.

b. ESX third-party update for Service Console kernel

    This update for the console OS kernel package resolves four
    security issues.

    1) IPv4 Remote Denial of Service

        An remote attacker can achieve a denial of service via an
        issue in the kernel IPv4 code.

        The Common Vulnerabilities and Exposures project
           (cve.mitre.org) has assigned the name CVE-2010-1188 to
           this issue.

    2) SCSI Driver Denial of Service / Possible Privilege Escalation

        A local attacker can achieve a denial of service and
        possibly a privilege escalation via a vulnerability in
        the Linux SCSI drivers.

        The Common Vulnerabilities and Exposures project
        (cve.mitre.org) has assigned the name CVE-2009-3080 to
        this issue.

    3) Kernel Memory Management Arbitrary Code Execution

        A context-dependent attacker can execute arbitrary code
        via a vulnerability in a kernel memory handling function.

        The Common Vulnerabilities and Exposures project
        (cve.mitre.org) has assigned the name CVE-2010-2240 to
        this issue.

    4) e1000 Driver Packet Filter Bypass

        There is an issue in the Service Console e1000 Linux
        driver for Intel PRO/1000 adapters that allows a remote
        attacker to bypass packet filters.

        The Common Vulnerabilities and Exposures project
        (cve.mitre.org) has assigned the name CVE-2009-4536 to
        this issue.

c. Multiple vulnerabilities in mount.vmhgfs

    This patch provides a fix for the following three security
    issues in the VMware Host Guest File System (HGFS). None of
    these issues affect Windows based Guest Operating Systems.

    1) Mount.vmhgfs Information Disclosure

        Information disclosure via a vulnerability that allows an
        attacker with access to the Guest to determine if a path
        exists in the Host filesystem and whether it is a file or
        directory regardless of permissions.

        The Common Vulnerabilities and Exposures project
        (cve.mitre.org) has assigned the name CVE-2011-2146 to
        this issue.

    2) Mount.vmhgfs Race Condition

        Privilege escalation via a race condition that allows an
        attacker with access to the guest to mount on arbitrary
        directories in the Guest filesystem and achieve privilege
        escalation if they can control the contents of the
        mounted directory.

        The Common Vulnerabilities and Exposures project
        (cve.mitre.org) has assigned the name CVE-2011-1787 to
        this issue.

    3) Mount.vmhgfs Privilege Escalation

        Privilege escalation via a procedural error that allows
        an attacker with access to the guest operating system to
        gain write access to an arbitrary file in the Guest
        filesystem.  This issue only affects Solaris and FreeBSD
        Guest Operating Systems.

        The Common Vulnerabilities and Exposures project
        (cve.mitre.org) has assigned the name CVE-2011-2145 to
        this issue.

    VMware would like to thank Dan Rosenberg for reporting these
    issues.

d. VI Client ActiveX vulnerabilities

    VI Client COM objects can be instantiated in Internet Explorer
    which may cause memory corruption. An attacker who succeeded in
    making the VI Client user visit a malicious Web site could
    execute code on the user's system within the security context of
    that user.

    VMware would like to thank Elazar Broad and iDefense for
    reporting this issue to us.

    The Common Vulnerabilities and Exposures Project (cve.mitre.org)
    has assigned the name CVE-2011-2217 to this issue.

    Affected versions.

    The vSphere Client which comes with vSphere 4.0 and vSphere 4.1
    is not affected. This is any build of vSphere Client Version
    4.0.0 and vSphere Client Version 4.1.0.

    VI Clients bundled with VMware Infrastructure 3 that are not
    affected are :
    - VI Client 2.0.2 Build 230598 and higher
    - VI Client 2.5 Build 204931 and higher

    The issue can be remediated by replacing an affected VI Client
    with the VI Client bundled with VirtualCenter 2.5 Update 6 or
    VirtualCenter 2.5 Update 6a."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2011/000158.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Tom Sawyer Software GET Extension Factory Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/06");
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


init_esx_check(date:"2011-06-02");
flag = 0;


if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-201105401-SG",
    patch_updates : make_list("ESX350-201205401-SG")
  )
) flag++;
if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201105404-SG")) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-201105406-SG",
    patch_updates : make_list("ESX350-201203402-BG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201104401-SG",
    patch_updates : make_list("ESX400-201111201-SG", "ESX400-201203401-SG", "ESX400-201205401-SG", "ESX400-201206401-SG", "ESX400-201209401-SG", "ESX400-201302401-SG", "ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201110410-SG",
    patch_updates : make_list("ESX400-Update04")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201104401-SG",
    patch_updates : make_list("ESX410-201110201-SG", "ESX410-201201401-SG", "ESX410-201204401-SG", "ESX410-201205401-SG", "ESX410-201206401-SG", "ESX410-201208101-SG", "ESX410-201211401-SG", "ESX410-201301401-SG", "ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201110225-SG",
    patch_updates : make_list("ESX410-Update02", "ESX410-Update03")
  )
) flag++;

if (esx_check(ver:"ESXi 3.5.0", patch:"ESXe350-201105401-I-SG")) flag++;
if (esx_check(ver:"ESXi 3.5.0", patch:"ESXe350-201105402-T-SG")) flag++;

if (
  esx_check(
    ver           : "ESXi 4.0",
    patch         : "ESXi400-201110401-SG",
    patch_updates : make_list("ESXi400-201203401-SG", "ESXi400-201205401-SG", "ESXi400-201206401-SG", "ESXi400-201209401-SG", "ESXi400-201302401-SG", "ESXi400-201305401-SG", "ESXi400-201310401-SG", "ESXi400-201404401-SG", "ESXi400-Update04")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.1",
    patch         : "ESXi410-201110201-SG",
    patch_updates : make_list("ESXi410-201201401-SG", "ESXi410-201204401-SG", "ESXi410-201205401-SG", "ESXi410-201206401-SG", "ESXi410-201208101-SG", "ESXi410-201211401-SG", "ESXi410-201301401-SG", "ESXi410-201304401-SG", "ESXi410-201307401-SG", "ESXi410-201312401-SG", "ESXi410-201404401-SG", "ESXi410-Update02", "ESXi410-Update03")
  )
) flag++;

if (esx_check(ver:"ESXi 5.0", vib:"VMware:net-e1000:8.0.3.1-2vmw.500.0.3.515841")) flag++;
if (esx_check(ver:"ESXi 5.0", vib:"VMware:net-e1000e:1.1.2-3vmw.500.0.3.515841")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
