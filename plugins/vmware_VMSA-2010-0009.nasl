#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2010-0009. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(46765);
  script_version("$Revision: 1.42 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id("CVE-2006-6304", "CVE-2007-4567", "CVE-2009-0590", "CVE-2009-1377", "CVE-2009-1378", "CVE-2009-1379", "CVE-2009-1384", "CVE-2009-1386", "CVE-2009-1387", "CVE-2009-2409", "CVE-2009-2695", "CVE-2009-2908", "CVE-2009-2910", "CVE-2009-3080", "CVE-2009-3228", "CVE-2009-3286", "CVE-2009-3547", "CVE-2009-3556", "CVE-2009-3563", "CVE-2009-3612", "CVE-2009-3613", "CVE-2009-3620", "CVE-2009-3621", "CVE-2009-3726", "CVE-2009-3736", "CVE-2009-3889", "CVE-2009-3939", "CVE-2009-4020", "CVE-2009-4021", "CVE-2009-4138", "CVE-2009-4141", "CVE-2009-4212", "CVE-2009-4272", "CVE-2009-4355", "CVE-2009-4536", "CVE-2009-4537", "CVE-2009-4538", "CVE-2010-0001", "CVE-2010-0097", "CVE-2010-0290", "CVE-2010-0382", "CVE-2010-0426", "CVE-2010-0427");
  script_bugtraq_id(31692, 34256, 35001, 35112, 35138, 35174, 35417, 36304, 36472, 36576, 36639, 36706, 36723, 36824, 36827, 36901, 36936, 37019, 37068, 37069, 37118, 37128, 37255, 37339, 37519, 37521, 37523, 37749, 37806, 37865, 37876, 37886, 38432);
  script_osvdb_id(31466, 52864, 54612, 54613, 54614, 54791, 55072, 55073, 56752, 57757, 57821, 58323, 58753, 58880, 59068, 59070, 59082, 59210, 59211, 59222, 59654, 59877, 60201, 60202, 60311, 60522, 60558, 60795, 60847, 61309, 61684, 61687, 61769, 61787, 61788, 61795, 61853, 61869, 62007, 62008, 62058, 62122, 62515, 62657);
  script_xref(name:"VMSA", value:"2010-0009");

  script_name(english:"VMSA-2010-0009 : ESXi ntp and ESX Service Console third-party updates");
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
"a. Service Console update for COS kernel

   Updated COS package 'kernel' addresses the security issues that are
   fixed through versions 2.6.18-164.11.1.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2009-2695, CVE-2009-2908, CVE-2009-3228,
   CVE-2009-3286, CVE-2009-3547, CVE-2009-3613 to the security issues
   fixed in kernel 2.6.18-164.6.1

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2009-3612, CVE-2009-3620, CVE-2009-3621,
   CVE-2009-3726 to the security issues fixed in kernel 2.6.18-164.9.1.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2007-4567, CVE-2009-4536, CVE-2009-4537,
   CVE-2009-4538 to the security issues fixed in kernel 2.6.18-164.10.1

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2006-6304, CVE-2009-2910, CVE-2009-3080,
   CVE-2009-3556, CVE-2009-3889, CVE-2009-3939, CVE-2009-4020,
   CVE-2009-4021, CVE-2009-4138, CVE-2009-4141, and CVE-2009-4272 to
   the security issues fixed in kernel 2.6.18-164.11.1.

b. ESXi userworld update for ntp

   The Network Time Protocol (NTP) is used to synchronize the time of
   a computer client or server to another server or reference time
   source.

   A vulnerability in ntpd could allow a remote attacker to cause a
   denial of service (CPU and bandwidth consumption) by using
   MODE_PRIVATE to send a spoofed (1) request or (2) response packet
   that triggers a continuous exchange of MODE_PRIVATE error responses
   between two NTP daemons.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-3563 to this issue.

c. Service Console package openssl updated to 0.9.8e-12.el5_4.1

   OpenSSL is a toolkit implementing SSL v2/v3 and TLS protocols with
   full-strength cryptography world-wide.

   A memory leak in the zlib could allow a remote attacker to cause a
   denial of service (memory consumption) via vectors that trigger
   incorrect calls to the CRYPTO_cleanup_all_ex_data function.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-4355 to this issue.

   A vulnerability was discovered which may allow remote attackers to
   spoof certificates by using MD2 design flaws to generate a hash
   collision in less than brute-force time. NOTE: the scope of this
   issue is currently limited because the amount of computation
   required is still large.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-2409 to this issue.

   This update also includes security fixes that were first addressed
   in version openssl-0.9.8e-12.el5.i386.rpm.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the names CVE-2009-0590, CVE-2009-1377, CVE-2009-1378,
   CVE-2009-1379, CVE-2009-1386 and CVE-2009-1387 to these issues.

d. Service Console update for krb5 to 1.6.1-36.el5_4.1 and pam_krb5 to
   2.2.14-15.

   Kerberos is a network authentication protocol. It is designed to
   provide strong authentication for client/server applications by
   using secret-key cryptography.

   Multiple integer underflows in the AES and RC4 functionality in the
   crypto library could allow remote attackers to cause a denial of
   service (daemon crash) or possibly execute arbitrary code by
   providing ciphertext with a length that is too short to be valid.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-4212 to this issue.

   The service console package for pam_krb5 is updated to version
   pam_krb5-2.2.14-15. This update fixes a flaw found in pam_krb5. In
   some non-default configurations (specifically, where pam_krb5 would
   be the first module to prompt for a password), a remote attacker
   could use this flaw to recognize valid usernames, which would aid a
   dictionary-based password guess attack.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-1384 to this issue.

e. Service Console package bind updated to 9.3.6-4.P1.el5_4.2

   BIND (Berkeley Internet Name Daemon) is by far the most widely used
   Domain Name System (DNS) software on the Internet.

   A vulnerability was discovered which could allow remote attacker to
   add the Authenticated Data (AD) flag to a forged NXDOMAIN response
   for an existing domain.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2010-0097 to this issue.

   A vulnerability was discovered which could allow remote attackers
   to conduct DNS cache poisoning attacks by receiving a recursive
   client query and sending a response that contains CNAME or DNAME
   records, which do not have the intended validation before caching.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2010-0290 to this issue.

   A vulnerability was found in the way that bind handles out-of-
   bailiwick data accompanying a secure response without re-fetching
   from the original source, which could allow remote attackers to
   have an unspecified impact via a crafted response.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2010-0382 to this issue.

   NOTE: ESX does not use the BIND name service daemon by default.

f. Service Console package gcc updated to 3.2.3-60

   The GNU Compiler Collection includes front ends for C, C++,
   Objective-C, Fortran, Java, and Ada, as well as libraries for these
   languages

   GNU Libtool's ltdl.c attempts to open .la library files in the
   current working directory.  This could allow a local user to gain
   privileges via a Trojan horse file.  The GNU C Compiler collection
   (gcc) provided in ESX contains a statically linked version of the
   vulnerable code, and is being replaced.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-3736 to this issue.

g. Service Console package gzip update to 1.3.3-15.rhel3

   gzip is a software application used for file compression

   An integer underflow in gzip's unlzw function on 64-bit platforms
   may allow a remote attacker to trigger an array index error
   leading to a denial of service (application crash) or possibly
   execute arbitrary code via a crafted LZW compressed file.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2010-0001 to this issue.

h. Service Console package sudo updated to 1.6.9p17-6.el5_4

   Sudo (su 'do') allows a system administrator to delegate authority
   to give certain users (or groups of users) the ability to run some
   (or all) commands as root or another user while providing an audit
   trail of the commands and their arguments.

   When a pseudo-command is enabled, sudo permits a match between the
   name of the pseudo-command and the name of an executable file in an
   arbitrary directory, which allows local users to gain privileges
   via a crafted executable file.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2010-0426 to this issue.

   When the runas_default option is used, sudo does not properly set
   group memberships, which allows local users to gain privileges via
   a sudo command.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2010-0427 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2010/000099.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 119, 189, 200, 264, 287, 310, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/01");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/18");
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


init_esx_check(date:"2010-05-27");
flag = 0;


if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201006405-SG")) flag++;
if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201006406-SG")) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-201006408-SG",
    patch_updates : make_list("ESX350-201008411-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.0.0",
    patch         : "ESX400-201005401-SG",
    patch_updates : make_list("ESX400-201009401-SG", "ESX400-201101401-SG", "ESX400-201103401-SG", "ESX400-201104401-SG", "ESX400-201110401-SG", "ESX400-201111201-SG", "ESX400-201203401-SG", "ESX400-201205401-SG", "ESX400-201206401-SG", "ESX400-201209401-SG", "ESX400-201302401-SG", "ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG", "ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0.0",
    patch         : "ESX400-201005405-SG",
    patch_updates : make_list("ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0.0",
    patch         : "ESX400-201005406-SG",
    patch_updates : make_list("ESX400-201009403-SG", "ESX400-201110403-SG", "ESX400-201203407-SG", "ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0.0",
    patch         : "ESX400-201005407-SG",
    patch_updates : make_list("ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0.0",
    patch         : "ESX400-201005408-SG",
    patch_updates : make_list("ESX400-201103407-SG", "ESX400-201305403-SG", "ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0.0",
    patch         : "ESX400-201005409-SG",
    patch_updates : make_list("ESX400-201009410-SG", "ESX400-201101404-SG", "ESX400-201305402-SG", "ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.0.0",
    patch         : "ESXi400-201005401-SG",
    patch_updates : make_list("ESXi400-201101401-SG", "ESXi400-201103401-SG", "ESXi400-201104401-SG", "ESXi400-201110401-SG", "ESXi400-201203401-SG", "ESXi400-201205401-SG", "ESXi400-201206401-SG", "ESXi400-201209401-SG", "ESXi400-201302401-SG", "ESXi400-201305401-SG", "ESXi400-201310401-SG", "ESXi400-201404401-SG", "ESXi400-Update02", "ESXi400-Update03", "ESXi400-Update04")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
