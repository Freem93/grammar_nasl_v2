#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2009-0004. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(40389);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id("CVE-2007-2953", "CVE-2008-2712", "CVE-2008-3432", "CVE-2008-4101", "CVE-2008-5077", "CVE-2009-0021", "CVE-2009-0025", "CVE-2009-0046", "CVE-2009-0047", "CVE-2009-0048", "CVE-2009-0049", "CVE-2009-0050", "CVE-2009-0051", "CVE-2009-0124", "CVE-2009-0125", "CVE-2009-0127", "CVE-2009-0128", "CVE-2009-0130");
  script_bugtraq_id(25095, 33150, 33151);
  script_osvdb_id(38674, 46306, 48971, 51164, 51368, 51434, 51435, 51436, 51437, 62878);
  script_xref(name:"VMSA", value:"2009-0004");

  script_name(english:"VMSA-2009-0004 : ESX Service Console updates for openssl, bind, and vim");
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
"a. Updated OpenSSL package for the Service Console fixes a
   security issue.

   OpenSSL 0.9.7a-33.24 and earlier does not properly check the return
   value from the EVP_VerifyFinal function, which could allow a remote
   attacker to bypass validation of the certificate chain via a
   malformed SSL/TLS signature for DSA and ECDSA keys.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2008-5077 to this issue.

b. Update bind package for the Service Console fixes a security issue.

   A flaw was discovered in the way Berkeley Internet Name Domain
   (BIND) checked the return value of the OpenSSL DSA_do_verify
   function. On systems using DNSSEC, a malicious zone could present
   a malformed DSA certificate and bypass proper certificate
   validation, allowing spoofing attacks.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2009-0025 to this issue.

c. Updated vim package for the Service Console addresses several
   security issues.

   Several input flaws were found in Visual editor IMproved's (Vim)
   keyword and tag handling. If Vim looked up a document's maliciously
   crafted tag or keyword, it was possible to execute arbitrary code as
   the user running Vim.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2008-4101 to this issue.

   A heap-based overflow flaw was discovered in Vim's expansion of file
   name patterns with shell wildcards. An attacker could create a
   specially crafted file or directory name, when opened by Vim causes
   the application to stop responding or execute arbitrary code.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2008-3432 to this issue.

   Several input flaws were found in various Vim system functions. If a
   user opened a specially crafted file, it was possible to execute
   arbitrary code as the user running Vim.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2008-2712 to this issue.

   A format string flaw was discovered in Vim's help tag processor. If
   a user was tricked into executing the 'helptags' command on
   malicious data, arbitrary code could be executed with the
   permissions of the user running VIM.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2007-2953 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2010/000077.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/27");
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


init_esx_check(date:"2009-03-31");
flag = 0;


if (esx_check(ver:"ESX 2.5.5", patch:"13")) flag++;

if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1008406")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1008408")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1008409")) flag++;

if (
  esx_check(
    ver           : "ESX 3.0.3",
    patch         : "ESX303-200903403-SG",
    patch_updates : make_list("ESX303-Rollup01", "ESX303-Update01")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.0.3",
    patch         : "ESX303-200903405-SG",
    patch_updates : make_list("ESX303-Rollup01", "ESX303-Update01")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.0.3",
    patch         : "ESX303-200903406-SG",
    patch_updates : make_list("ESX303-Rollup01", "ESX303-Update01")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200904406-SG",
    patch_updates : make_list("ESX350-Update05", "ESX350-Update05a")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200904407-SG",
    patch_updates : make_list("ESX350-201002404-SG", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200904408-SG",
    patch_updates : make_list("ESX350-201012401-SG", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-200912402-SG",
    patch_updates : make_list("ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
