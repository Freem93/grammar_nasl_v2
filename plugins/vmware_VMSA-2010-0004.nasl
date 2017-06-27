#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2010-0004. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(44993);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id("CVE-2008-3916", "CVE-2008-4316", "CVE-2008-4552", "CVE-2009-0115", "CVE-2009-0590", "CVE-2009-1189", "CVE-2009-1377", "CVE-2009-1378", "CVE-2009-1379", "CVE-2009-1386", "CVE-2009-1387", "CVE-2009-2695", "CVE-2009-2849", "CVE-2009-2904", "CVE-2009-2905", "CVE-2009-2908", "CVE-2009-3228", "CVE-2009-3286", "CVE-2009-3547", "CVE-2009-3560", "CVE-2009-3563", "CVE-2009-3612", "CVE-2009-3613", "CVE-2009-3620", "CVE-2009-3621", "CVE-2009-3720", "CVE-2009-3726", "CVE-2009-4022");
  script_bugtraq_id(30815, 31602, 31823, 34100, 34256, 35001, 35138, 35174, 36304, 36515, 36552, 36639, 36706, 36723, 36824, 36827, 36901, 36936, 37118, 37203, 37255);
  script_osvdb_id(48045, 49182, 52864, 53486, 54612, 54613, 54614, 55072, 55073, 56165, 56386, 57209, 57757, 57821, 58323, 58330, 58495, 58880, 59068, 59070, 59210, 59211, 59222, 59654, 59737, 59877, 60493, 60797, 60847);
  script_xref(name:"VMSA", value:"2010-0004");

  script_name(english:"VMSA-2010-0004 : ESX Service Console and vMA third-party updates");
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
"a. vMA and Service Console update for newt to 0.52.2-12.el5_4.1

   Newt is a programming library for color text mode, widget based
   user interfaces. Newt can be used to add stacked windows, entry
   widgets, checkboxes, radio buttons, labels, plain text fields,
   scrollbars, etc., to text mode user interfaces.

   A heap-based buffer overflow flaw was found in the way newt
   processes content that is to be displayed in a text dialog box.
   A local attacker could issue a specially crafted text dialog box
   display request (direct or via a custom application), leading to a
   denial of service (application crash) or, potentially, arbitrary
   code execution with the privileges of the user running the
   application using the newt library.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-2905 to this issue.

b. vMA and Service Console update for vMA package nfs-utils to
   1.0.9-42.el5

   The nfs-utils package provides a daemon for the kernel NFS server
   and related tools.

   It was discovered that nfs-utils did not use tcp_wrappers
   correctly.  Certain hosts access rules defined in '/etc/hosts.allow'
   and '/etc/hosts.deny' may not have been honored, possibly allowing
   remote attackers to bypass intended access restrictions.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2008-4552 to this issue.

c. vMA and Service Console package glib2 updated to 2.12.3-4.el5_3.1

   GLib is the low-level core library that forms the basis for
   projects such as GTK+ and GNOME. It provides data structure
   handling for C, portability wrappers, and interfaces for such
   runtime functionality as an event loop, threads, dynamic loading,
   and an object system.

   Multiple integer overflows in glib/gbase64.c in GLib before 2.20
   allow context-dependent attackers to execute arbitrary code via a
   long string that is converted either from or to a base64
   representation.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2008-4316 to this issue.

d. vMA and Service Console update for openssl to 0.9.8e-12.el5

   SSL is a toolkit implementing SSL v2/v3 and TLS protocols with full-
   strength cryptography world-wide.

   Multiple denial of service flaws were discovered in OpenSSL's DTLS
   implementation. A remote attacker could use these flaws to cause a
   DTLS server to use excessive amounts of memory, or crash on an
   invalid memory access or NULL pointer dereference.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the names CVE-2009-1377, CVE-2009-1378,
   CVE-2009-1379, CVE-2009-1386, CVE-2009-1387 to these issues.

   An input validation flaw was found in the handling of the BMPString
   and UniversalString ASN1 string types in OpenSSL's
   ASN1_STRING_print_ex() function. An attacker could use this flaw to
   create a specially crafted X.509 certificate that could cause
   applications using the affected function to crash when printing
   certificate contents.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-0590 to this issue.

e. vMA and Service Console package bind updated to 9.3.6-4.P1.el5_4.1

   It was discovered that BIND was incorrectly caching responses
   without performing proper DNSSEC validation, when those responses
   were received during the resolution of a recursive client query
   that requested DNSSEC records but indicated that checking should be
   disabled. A remote attacker could use this flaw to bypass the DNSSEC
   validation check and perform a cache poisoning attack if the target
   BIND server was receiving such client queries.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-4022 to this issue.

f. vMA and Service Console package expat updated to 1.95.8-8.3.el5_4.2.

   Two buffer over-read flaws were found in the way Expat handled
   malformed UTF-8 sequences when processing XML files. A specially-
   crafted XML file could cause applications using Expat to fail while
   parsing the file.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the names CVE-2009-3560 and CVE-2009-3720 to these
   issues.

g. vMA and Service Console package openssh update to 4.3p2-36.el5_4.2

   A Red Hat specific patch used in the openssh packages as shipped in
   Red Hat Enterprise Linux 5.4 (RHSA-2009:1287) loosened certain
   ownership requirements for directories used as arguments for the
   ChrootDirectory configuration options. A malicious user that also
   has or previously had non-chroot shell access to a system could
   possibly use this flaw to escalate their privileges and run
   commands as any system user.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-2904 to this issue.

h. vMA and Service Console package ntp updated to
   ntp-4.2.2p1-9.el5_4.1.i386.rpm

   A flaw was discovered in the way ntpd handled certain malformed NTP
   packets. ntpd logged information about all such packets and replied
   with an NTP packet that was treated as malformed when received by
   another ntpd. A remote attacker could use this flaw to create an NTP
   packet reply loop between two ntpd servers through a malformed packet
   with a spoofed source IP address and port, causing ntpd on those
   servers to use excessive amounts of CPU time and fill disk space with
   log messages.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-3563 to this issue.   

i. vMA update for package kernel to 2.6.18-164.9.1.el5

   Updated vMA package kernel addresses the security issues listed
   below.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2009-2849 to the security issue fixed in
   kernel 2.6.18-128.2.1

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2009-2695, CVE-2009-2908, CVE-2009-3228,
   CVE-2009-3286, CVE-2009-3547, CVE-2009-3613 to the security issues
   fixed in kernel 2.6.18-128.6.1

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2009-3612, CVE-2009-3620, CVE-2009-3621,
   CVE-2009-3726 to the security issues fixed in kernel
   2.6.18-128.9.1

j. vMA 4.0 updates for the packages kpartx, libvolume-id,
   device-mapper-multipath, fipscheck, dbus, dbus-libs, and ed

   kpartx updated to 0.4.7-23.el5_3.4, libvolume-id updated to
   095-14.20.el5 device-mapper-multipath package updated to
   0.4.7-23.el5_3.4, fipscheck updated to 1.0.3-1.el5, dbus
   updated to 1.1.2-12.el5, dbus-libs updated to 1.1.2-12.el5,
   and ed package updated to 0.2-39.el5_2.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the names CVE-2008-3916, CVE-2009-1189 and
   CVE-2009-0115 to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2010/000104.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(16, 20, 119, 189, 200, 264, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/05");
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


init_esx_check(date:"2010-03-03");
flag = 0;


if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201006407-SG")) flag++;
if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201008406-SG")) flag++;

if (
  esx_check(
    ver           : "ESX 4.0.0",
    patch         : "ESX400-201002404-SG",
    patch_updates : make_list("ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0.0",
    patch         : "ESX400-201002406-SG",
    patch_updates : make_list("ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0.0",
    patch         : "ESX400-201002407-SG",
    patch_updates : make_list("ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0.0",
    patch         : "ESX400-201005403-SG",
    patch_updates : make_list("ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0.0",
    patch         : "ESX400-201005404-SG",
    patch_updates : make_list("ESX400-201404402-SG", "ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
