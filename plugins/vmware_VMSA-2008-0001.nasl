#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2008-0001. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(40372);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id("CVE-2007-3108", "CVE-2007-4572", "CVE-2007-5116", "CVE-2007-5135", "CVE-2007-5191", "CVE-2007-5360", "CVE-2007-5398");
  script_bugtraq_id(21663, 25163, 25831, 26350, 26454, 26455, 26701, 27497, 27686, 29003, 29076, 29404);
  script_osvdb_id(29262, 37055, 39179, 39180, 40083, 40409, 40912);
  script_xref(name:"VMSA", value:"2008-0001");

  script_name(english:"VMSA-2008-0001 : Moderate OpenPegasus PAM Authentication Buffer Overflow and updated service console packages");
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
"I   Service Console package security updates

  a. OpenPegasus PAM Authentication Buffer Overflow

  Alexander Sotirov from VMware Security Research discovered a
  buffer overflow vulnerability in the OpenPegasus Management server.
  This flaw could be exploited by a malicious remote user on the
  service console network to gain root access to the service console.

  The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CVE-2007-5360 to this issue.

  b.   Updated Samba package

       An issue where attackers on the service console management
       network can cause a stack-based buffer overflow in the
       reply_netbios_packet function of nmbd in Samba. On systems
       where Samba is being used as a WINS server, exploiting this
       vulnerability can allow remote attackers to execute arbitrary
       code via crafted WINS Name Registration requests followed by a
       WINS Name Query request.

       An issue where attackers on the service console management
       network can exploit a vulnerability that occurs when Samba is
       configured as a Primary or Backup Domain controller. The
       vulnerability allows remote attackers to have an unknown impact
       via crafted GETDC mailslot requests, related to handling of
       GETDC logon server requests.

       The Common Vulnerabilities and Exposures project (cve.mitre.org)
       has assigned the names CVE-2007-5398 and CVE-2007-4572 to these
       issues.

 Note: By default Samba is not configured as a WINS server or a domain
       controller and ESX is not vulnerable unless the administrator
       has changed the default configuration.

       This vulnerability can be exploited remotely only if the
       attacker has access to the service console network.

       Security best practices provided by VMware recommend that the
       service console be isolated from the VM network. Please see
       http://www.vmware.com/resources/techresources/726 for more
       information on VMware security best practices.

  c.   Updated util-linux package

       The patch addresses an issue where the mount and umount
       utilities in util-linux call the setuid and setgid functions in
       the wrong order and do not check the return values, which could
       allow attackers to gain elevated privileges via helper
       application such as mount.nfs.

       The Common Vulnerabilities and Exposures project (cve.mitre.org)
       has assigned the name CVE-2007-5191 to this issue.

  d.   Updated Perl package

       The update addresses an issue where the regular expression
       engine in Perl can be used to issue a specially crafted regular
       expression that allows the attacker to run arbitrary code with
       the permissions level of the current Perl user.

       The Common Vulnerabilities and Exposures project (cve.mitre.org)
       has assigned the name CVE-2007-5116 to this issue.

  e.   Updated OpenSSL package

       A flaw in the SSL_get_shared_ciphers() function could allow an
       attacker to cause a buffer overflow problem by sending ciphers
       to applications that use the function.

       The Common Vulnerabilities and Exposures project (cve.mitre.org)
       has assigned the names CVE-2007-3108, and CVE-2007-5135 to these
       issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2008/000004.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119, 189, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/28");
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


init_esx_check(date:"2008-01-07");
flag = 0;


if (esx_check(ver:"ESX 2.5.5", patch:"14")) flag++;
if (esx_check(ver:"ESX 2.5.5", patch:"3")) flag++;

if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1002962")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1002963")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1002964")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1002968")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1002972")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1003176")) flag++;

if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1002969")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1002970")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1002971")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1002975")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1002976")) flag++;

if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200712402-SG",
    patch_updates : make_list("ESX350-201008410-SG", "ESX350-201012408-SG", "ESX350-Update05a")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200712403-SG",
    patch_updates : make_list("ESX350-Update05a")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200712404-SG",
    patch_updates : make_list("ESX350-201008412-SG", "ESX350-Update05a")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
