#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2009-0016. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(42870);
  script_version("$Revision: 1.42 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id("CVE-2007-2052", "CVE-2007-4965", "CVE-2007-5333", "CVE-2007-5342", "CVE-2007-5461", "CVE-2007-5966", "CVE-2007-6286", "CVE-2008-0002", "CVE-2008-1232", "CVE-2008-1721", "CVE-2008-1887", "CVE-2008-1947", "CVE-2008-2315", "CVE-2008-2370", "CVE-2008-3142", "CVE-2008-3143", "CVE-2008-3144", "CVE-2008-3528", "CVE-2008-4307", "CVE-2008-4864", "CVE-2008-5031", "CVE-2008-5515", "CVE-2008-5700", "CVE-2009-0028", "CVE-2009-0033", "CVE-2009-0159", "CVE-2009-0269", "CVE-2009-0322", "CVE-2009-0580", "CVE-2009-0675", "CVE-2009-0676", "CVE-2009-0696", "CVE-2009-0745", "CVE-2009-0746", "CVE-2009-0747", "CVE-2009-0748", "CVE-2009-0778", "CVE-2009-0781", "CVE-2009-0783", "CVE-2009-0787", "CVE-2009-0834", "CVE-2009-1072", "CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1099", "CVE-2009-1100", "CVE-2009-1101", "CVE-2009-1102", "CVE-2009-1103", "CVE-2009-1104", "CVE-2009-1105", "CVE-2009-1106", "CVE-2009-1107", "CVE-2009-1192", "CVE-2009-1252", "CVE-2009-1336", "CVE-2009-1337", "CVE-2009-1385", "CVE-2009-1388", "CVE-2009-1389", "CVE-2009-1439", "CVE-2009-1630", "CVE-2009-1633", "CVE-2009-1895", "CVE-2009-2406", "CVE-2009-2407", "CVE-2009-2414", "CVE-2009-2416", "CVE-2009-2417", "CVE-2009-2625", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2675", "CVE-2009-2676", "CVE-2009-2692", "CVE-2009-2698", "CVE-2009-2716", "CVE-2009-2718", "CVE-2009-2719", "CVE-2009-2720", "CVE-2009-2721", "CVE-2009-2722", "CVE-2009-2723", "CVE-2009-2724", "CVE-2009-2847", "CVE-2009-2848");
  script_bugtraq_id(25696, 26070, 26880, 27006, 27703, 27706, 28715, 28749, 29502, 30491, 30494, 30496, 31932, 31976, 33187, 33846, 33951, 34205, 34240, 34405, 34453, 34481, 34612, 34673, 34934, 35017, 35185, 35193, 35196, 35263, 35281, 35416, 35647, 35848, 35850, 35851, 35922, 35930, 35939, 35943, 35944, 35946, 35958, 36010, 36032, 36038, 36108);
  script_osvdb_id(35247, 38187, 39833, 40142, 40248, 41434, 41435, 41436, 44693, 44730, 45905, 47462, 47463, 47478, 47480, 47481, 49088, 50092, 50093, 50094, 50095, 50096, 50097, 51000, 51606, 51653, 52198, 52201, 52202, 52203, 52204, 52364, 52461, 52631, 52633, 52860, 52861, 52899, 53164, 53165, 53166, 53167, 53168, 53169, 53170, 53171, 53172, 53173, 53174, 53175, 53176, 53177, 53178, 53312, 53362, 53593, 53629, 53951, 54379, 54492, 54498, 54576, 54892, 55053, 55054, 55055, 55056, 55181, 55679, 55807, 56444, 56584, 56690, 56691, 56783, 56784, 56785, 56786, 56788, 56955, 56956, 56957, 56958, 56959, 56960, 56961, 56962, 56964, 56984, 56985, 56990, 56992, 56994, 57208, 57264, 57431, 57462);
  script_xref(name:"VMSA", value:"2009-0016");

  script_name(english:"VMSA-2009-0016 : VMware vCenter and ESX update release and vMA patch release address multiple security issues in third party components.");
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
"a. JRE Security Update

  JRE update to version 1.5.0_20, which addresses multiple security
  issues that existed in earlier releases of JRE.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the following names to the security issues fixed in
  JRE 1.5.0_18: CVE-2009-1093, CVE-2009-1094, CVE-2009-1095,
  CVE-2009-1096, CVE-2009-1097, CVE-2009-1098, CVE-2009-1099,
  CVE-2009-1100, CVE-2009-1101, CVE-2009-1102, CVE-2009-1103,
  CVE-2009-1104, CVE-2009-1105, CVE-2009-1106, and CVE-2009-1107.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the following names to the security issues fixed in
  JRE 1.5.0_20: CVE-2009-2625, CVE-2009-2670, CVE-2009-2671,
  CVE-2009-2672, CVE-2009-2673, CVE-2009-2675, CVE-2009-2676,
  CVE-2009-2716, CVE-2009-2718, CVE-2009-2719, CVE-2009-2720,
  CVE-2009-2721, CVE-2009-2722, CVE-2009-2723, CVE-2009-2724.

b. Update Apache Tomcat version

  Update for VirtualCenter and ESX patch update the Tomcat package to
  version 6.0.20 (vSphere 4.0) or version 5.5.28 (VirtualCenter 2.5)
  which addresses multiple security issues that existed
  in the previous version of Apache Tomcat.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the following names to the security issues fixed in
  Apache Tomcat 6.0.20 and Tomcat 5.5.28: CVE-2008-5515,
  CVE-2009-0033, CVE-2009-0580, CVE-2009-0781, CVE-2009-0783.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the following names to the security issues fixed in
  Apache Tomcat 6.0.18:  CVE-2008-1232, CVE-2008-1947, CVE-2008-2370.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the following names to the security issues fixed in
  Apache Tomcat 6.0.16:  CVE-2007-5333, CVE-2007-5342, CVE-2007-5461,
  CVE-2007-6286, CVE-2008-0002.
 
 c. Third-party library update for ntp.
 
  The Network Time Protocol (NTP) is used to synchronize a computer's
  time with a referenced time source.
 
  ESXi 3.5 and ESXi 4.0 have a ntp client that is affected by the
  following security issue. Note that the same security issue is
  present in the ESX Service Console as described in section d. of
  this advisory.
 
  A buffer overflow flaw was discovered in the ntpd daemon's NTPv4
  authentication code. If ntpd was configured to use public key
  cryptography for NTP packet authentication, a remote attacker could
  use this flaw to send a specially crafted request packet that could
  crash ntpd or, potentially, execute arbitrary code with the
  privileges of the 'ntp' user.
 
  The Common Vulnerabilities and Exposures Project (cve.mitre.org)
  has assigned the name CVE-2009-1252 to this issue.
 
  The NTP security issue identified by CVE-2009-0159 is not relevant
  for ESXi 3.5 and ESXi 4.0.
 
d. Service Console update for ntp

  Service Console package ntp updated to version ntp-4.2.2pl-9el5_3.2
 
  The Network Time Protocol (NTP) is used to synchronize a computer's
  time with a referenced time source.
 
  The Service Console present in ESX is affected by the following
  security issues.
 
  A buffer overflow flaw was discovered in the ntpd daemon's NTPv4
  authentication code. If ntpd was configured to use public key
  cryptography for NTP packet authentication, a remote attacker could
  use this flaw to send a specially crafted request packet that could
  crash ntpd or, potentially, execute arbitrary code with the
  privileges of the 'ntp' user.
 
  NTP authentication is not enabled by default on the Service Console.
 
  The Common Vulnerabilities and Exposures Project (cve.mitre.org)
  has assigned the name CVE-2009-1252 to this issue.
 
  A buffer overflow flaw was found in the ntpq diagnostic command. A
  malicious, remote server could send a specially crafted reply to an
  ntpq request that could crash ntpq or, potentially, execute
  arbitrary code with the privileges of the user running the ntpq
  command.
 
  The Common Vulnerabilities and Exposures Project (cve.mitre.org)
  has assigned the name CVE-2009-0159 to this issue.
 
 e. Updated Service Console package kernel

  Updated Service Console package kernel addresses the security
  issues listed below.

  The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the names CVE-2008-3528, CVE-2008-5700, CVE-2009-0028,
  CVE-2009-0269, CVE-2009-0322, CVE-2009-0675, CVE-2009-0676,
  CVE-2009-0778 to the security issues fixed in kernel
  2.6.18-128.1.6.

  The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the names CVE-2008-4307, CVE-2009-0834, CVE-2009-1337,
  CVE-2009-0787, CVE-2009-1336 to the security issues fixed in
  kernel 2.6.18-128.1.10.

  The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the names CVE-2009-1439, CVE-2009-1633, CVE-2009-1072,
  CVE-2009-1630, CVE-2009-1192 to the security issues fixed in
  kernel 2.6.18-128.1.14.

  The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the names CVE-2007-5966, CVE-2009-1385, CVE-2009-1388,
  CVE-2009-1389, CVE-2009-1895, CVE-2009-2406, CVE-2009-2407 to the
  security issues fixed in kernel 2.6.18-128.4.1.

  The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the names CVE-2009-2692, CVE-2009-2698 to the
  security issues fixed in kernel 2.6.18-128.7.1.

  The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the names CVE-2009-0745, CVE-2009-0746, CVE-2009-0747,
  CVE-2009-0748, CVE-2009-2847, CVE-2009-2848 to the security issues
  fixed in kernel 2.6.18-164.

 f. Updated Service Console package python

  Service Console package Python update to version 2.4.3-24.el5.

  When the assert() system call was disabled, an input sanitization
  flaw was revealed in the Python string object implementation that
  led to a buffer overflow. The missing check for negative size values
  meant the Python memory allocator could allocate less memory than
  expected. This could result in arbitrary code execution with the
  Python interpreter's privileges.

  Multiple buffer and integer overflow flaws were found in the Python
  Unicode string processing and in the Python Unicode and string
  object implementations. An attacker could use these flaws to cause
  a denial of service.

  Multiple integer overflow flaws were found in the Python imageop
  module. If a Python application used the imageop module to
  process untrusted images, it could cause the application to
  disclose sensitive information, crash or, potentially, execute
  arbitrary code with the Python interpreter's privileges.

  Multiple integer underflow and overflow flaws were found in the
  Python snprintf() wrapper implementation. An attacker could use
  these flaws to cause a denial of service (memory corruption).

  Multiple integer overflow flaws were found in various Python
  modules. An attacker could use these flaws to cause a denial of
  service.

  An integer signedness error, leading to a buffer overflow, was
  found in the Python zlib extension module. If a Python application
  requested the negative byte count be flushed for a decompression
  stream, it could cause the application to crash or, potentially,
  execute arbitrary code with the Python interpreter's privileges.

  A flaw was discovered in the strxfrm() function of the Python
  locale module. Strings generated by this function were not properly
  NULL-terminated, which could possibly cause disclosure of data
  stored in the memory of a Python application using this function.

  The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the names CVE-2007-2052 CVE-2007-4965 CVE-2008-1721
  CVE-2008-1887 CVE-2008-2315 CVE-2008-3142 CVE-2008-3143
  CVE-2008-3144 CVE-2008-4864 CVE-2008-5031 to these issues.

 g. Updated Service Console package bind

  Service Console package bind updated to version 9.3.6-4.P1.el5

  The Berkeley Internet Name Domain (BIND) is an implementation of the
  Domain Name System (DNS) protocols. BIND includes a DNS server
  (named); a resolver library (routines for applications to use when
  interfacing with DNS); and tools for verifying that the DNS server
  is operating correctly.

  A flaw was found in the way BIND handles dynamic update message
  packets containing the 'ANY' record type. A remote attacker could
  use this flaw to send a specially crafted dynamic update packet
  that could cause named to exit with an assertion failure.

  The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CVE-2009-0696 to this issue.

 h. Updated Service Console package libxml2

  Service Console package libxml2 updated to version 2.6.26-2.1.2.8.

  libxml is a library for parsing and manipulating XML files. A
  Document Type Definition (DTD) defines the legal syntax (and also
  which elements can be used) for certain types of files, such as XML
  files.

  A stack overflow flaw was found in the way libxml processes the
  root XML document element definition in a DTD. A remote attacker
  could provide a specially crafted XML file, which once opened by a
  local, unsuspecting user, would lead to denial of service.

  Multiple use-after-free flaws were found in the way libxml parses
  the Notation and Enumeration attribute types. A remote attacker
  could provide a specially crafted XML file, which once opened by a
  local, unsuspecting user, would lead to denial of service.

  The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the names CVE-2009-2414 and CVE-2009-2416 to these
  issues.

 i. Updated Service Console package curl

  Service Console package curl updated to version 7.15.5-2.1.el5_3.5

  A cURL is affected by the previously published 'null prefix attack',
  caused by incorrect handling of NULL characters in X.509
  certificates. If an attacker is able to get a carefully-crafted
  certificate signed by a trusted Certificate Authority, the attacker
  could use the certificate during a man-in-the-middle attack and
  potentially confuse cURL into accepting it by mistake.

  The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CVE-2009-2417 to this issue

 j. Updated Service Console package gnutls

  Service Console package gnutil updated to version 1.4.1-3.el5_3.5

  A flaw was discovered in the way GnuTLS handles NULL characters in
  certain fields of X.509 certificates. If an attacker is able to get
  a carefully-crafted certificate signed by a Certificate Authority
  trusted by an application using GnuTLS, the attacker could use the
  certificate during a man-in-the-middle attack and potentially
  confuse the application into accepting it by mistake.

  The Common Vulnerabilities and Exposures project (cve.mitre.org)
  has assigned the name CVE-2009-2730 to this issue"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2010/000087.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:X/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel Sendpage Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(16, 20, 22, 79, 94, 119, 189, 200, 264, 310, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/31");
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


init_esx_check(date:"2009-11-20");
flag = 0;


if (esx_check(ver:"ESX 3.0.3", patch:"ESX303-201002204-SG")) flag++;
if (esx_check(ver:"ESX 3.0.3", patch:"ESX303-201002205-SG")) flag++;
if (esx_check(ver:"ESX 3.0.3", patch:"ESX303-201002206-SG")) flag++;

if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201002402-SG")) flag++;
if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201002404-SG")) flag++;
if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201002407-SG")) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-201003403-SG",
    patch_updates : make_list("ESX350-201203401-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-200911201-UG",
    patch_updates : make_list("ESX400-Update01a", "ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-200911223-UG",
    patch_updates : make_list("ESX400-Update01a", "ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-200911232-SG",
    patch_updates : make_list("ESX400-201009409-SG", "ESX400-201203403-SG", "ESX400-Update01a", "ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-200911233-SG",
    patch_updates : make_list("ESX400-Update01a", "ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-200911234-SG",
    patch_updates : make_list("ESX400-201209402-SG", "ESX400-201305404-SG", "ESX400-201310402-SG", "ESX400-Update01a", "ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-200911235-SG",
    patch_updates : make_list("ESX400-201203402-SG", "ESX400-Update01a", "ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-200911237-SG",
    patch_updates : make_list("ESX400-201005408-SG", "ESX400-201103407-SG", "ESX400-201305403-SG", "ESX400-Update01a", "ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-200911238-SG",
    patch_updates : make_list("ESX400-201005404-SG", "ESX400-201404402-SG", "ESX400-Update01a", "ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;

if (esx_check(ver:"ESXi 3.5.0", patch:"ESXe350-201002401-O-SG")) flag++;

if (esx_check(ver:"ESXi 4.0", patch:"ESXi400-200911201-UG")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
