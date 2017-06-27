#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2012-0009. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(58977);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id("CVE-2012-1516", "CVE-2012-1517", "CVE-2012-2448", "CVE-2012-2449", "CVE-2012-2450");
  script_bugtraq_id(53369, 53371);
  script_osvdb_id(81691, 81692, 81693, 81694, 81695);
  script_xref(name:"VMSA", value:"2012-0009");

  script_name(english:"VMSA-2012-0009 : VMware Workstation, Player, Fusion, ESXi and ESX patches address critical security issues");
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
"a. VMware host memory overwrite vulnerability (data pointers)

   Due to a flaw in the handler function for RPC commands, it is
   possible to manipulate data pointers within the VMX process.
   This vulnerability may allow a guest user to crash the VMX
   process or potentially execute code on the host.

   Workaround

   - Configure virtual machines to use less than 4 GB of memory.
     Virtual machines that have less than 4GB of memory are not
     affected.

     OR

   - Disable VIX messages from each guest VM by editing the
     configuration file (.vmx) for the virtual machine as described
     in VMware Knowledge Base article 1714. Add the following line :
     isolation.tools.vixMessage.disable = 'TRUE'.
     Note: This workaround is not valid for Workstation 7.x and
           Fusion 3.x

   Mitigation

   - Do not allow untrusted users access to your virtual machines.
     Root or Administrator level permissions are not required to
     exploit this issue.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2012-1516 to this issue.

   VMware would like to thank Derek Soeder of Ridgeway Internet
   Security, L.L.C. for reporting this issue to us.

b. VMware host memory overwrite vulnerability (function pointers)

   Due to a flaw in the handler function for RPC commands, it is
   possible to manipulate function pointers within the VMX process.
   This vulnerability may allow a guest user to crash the VMX
   process or potentially execute code on the host.

   Workaround

   - None identified

   Mitigation

   - Do not allow untrusted users access to your virtual machines.
     Root or Administrator level permissions are not required to
     exploit this issue.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2012-1517 to this issue.

   VMware would like to thank Derek Soeder of Ridgeway Internet
   Security, L.L.C. for reporting this issue to us.

c. ESX NFS traffic parsing vulnerability

   Due to a flaw in the handling of NFS traffic, it is possible to
   overwrite memory. This vulnerability may allow a user with
   access to the network to execute code on the ESXi/ESX host
   without authentication. The issue is not present in cases where
   there is no NFS traffic.

   Workaround
   - None identified

   Mitigation
   - Connect only to trusted NFS servers
   - Segregate the NFS network
   - Harden your NFS server

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2012-2448 to this issue.

d. VMware floppy device out-of-bounds memory write

   Due to a flaw in the virtual floppy configuration it is possible
   to perform an out-of-bounds memory write. This vulnerability may
   allow a guest user to crash the VMX process or potentially
   execute code on the host.

   Workaround

   - Remove the virtual floppy drive from the list of virtual IO
     devices. The VMware hardening guides recommend removing unused
     virtual IO devices in general.

   Mitigation

   - Do not allow untrusted root users in your virtual
     machines. Root or Administrator level permissions are required
     to exploit this issue.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2012-2449 to this issue.

e. VMware SCSI device unchecked memory write

   Due to a flaw in the SCSI device registration it is possible to
   perform an unchecked write into memory. This vulnerability may
   allow a guest user to crash the VMX process or potentially
   execute code on the host.

   Workaround

   - Remove the virtual SCSI controller from the list of virtual IO
     devices. The VMware hardening guides recommend removing unused
     virtual IO devices in general.

   Mitigation

   - Do not allow untrusted root users access to your virtual
     machines.  Root or Administrator level permissions are
     required to exploit this issue.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2012-2450 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2012/000182.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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


init_esx_check(date:"2012-05-03");
flag = 0;


if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201205401-SG")) flag++;

if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201105201-UG",
    patch_updates : make_list("ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201205401-SG",
    patch_updates : make_list("ESX400-201206401-SG", "ESX400-201209401-SG", "ESX400-201302401-SG", "ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201110201-SG",
    patch_updates : make_list("ESX410-201201401-SG", "ESX410-201204401-SG", "ESX410-201205401-SG", "ESX410-201206401-SG", "ESX410-201208101-SG", "ESX410-201211401-SG", "ESX410-201301401-SG", "ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201201401-SG",
    patch_updates : make_list("ESX410-201204401-SG", "ESX410-201205401-SG", "ESX410-201206401-SG", "ESX410-201208101-SG", "ESX410-201211401-SG", "ESX410-201301401-SG", "ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201205401-SG",
    patch_updates : make_list("ESX410-201206401-SG", "ESX410-201208101-SG", "ESX410-201211401-SG", "ESX410-201301401-SG", "ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG", "ESX410-Update03")
  )
) flag++;

if (esx_check(ver:"ESXi 3.5.0", patch:"ESXe350-201205401-I-SG")) flag++;

if (esx_check(ver:"ESXi 4.0", patch:"ESXi400-201105201-UG")) flag++;
if (
  esx_check(
    ver           : "ESXi 4.0",
    patch         : "ESXi400-201205401-SG",
    patch_updates : make_list("ESXi400-201206401-SG", "ESXi400-201209401-SG", "ESXi400-201302401-SG", "ESXi400-201305401-SG", "ESXi400-201310401-SG", "ESXi400-201404401-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.1",
    patch         : "ESXi410-201110201-SG",
    patch_updates : make_list("ESXi410-201201401-SG", "ESXi410-201204401-SG", "ESXi410-201205401-SG", "ESXi410-201206401-SG", "ESXi410-201208101-SG", "ESXi410-201211401-SG", "ESXi410-201301401-SG", "ESXi410-201304401-SG", "ESXi410-201307401-SG", "ESXi410-201312401-SG", "ESXi410-201404401-SG", "ESXi410-Update02", "ESXi410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESXi 4.1",
    patch         : "ESXi410-201201401-SG",
    patch_updates : make_list("ESXi410-201204401-SG", "ESXi410-201205401-SG", "ESXi410-201206401-SG", "ESXi410-201208101-SG", "ESXi410-201211401-SG", "ESXi410-201301401-SG", "ESXi410-201304401-SG", "ESXi410-201307401-SG", "ESXi410-201312401-SG", "ESXi410-201404401-SG", "ESXi410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESXi 4.1",
    patch         : "ESXi410-201205401-SG",
    patch_updates : make_list("ESXi410-201206401-SG", "ESXi410-201208101-SG", "ESXi410-201211401-SG", "ESXi410-201301401-SG", "ESXi410-201304401-SG", "ESXi410-201307401-SG", "ESXi410-201312401-SG", "ESXi410-201404401-SG", "ESXi410-Update03")
  )
) flag++;

if (esx_check(ver:"ESXi 5.0", vib:"VMware:esx-base:5.0.0-1.13.702118")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
