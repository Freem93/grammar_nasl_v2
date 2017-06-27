#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2010-0015. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(49703);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id("CVE-2009-2409", "CVE-2009-3245", "CVE-2009-3555", "CVE-2009-3767", "CVE-2010-0433", "CVE-2010-0734", "CVE-2010-0826", "CVE-2010-1646");
  script_bugtraq_id(36844, 36881, 36935, 38162, 38533, 38562, 39132, 40538);
  script_osvdb_id(56752, 59268, 59971, 62217, 62719, 62844, 63638, 65083);
  script_xref(name:"VMSA", value:"2010-0015");

  script_name(english:"VMSA-2010-0015 : VMware ESX third-party updates for Service Console");
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
"a. Service Console update for NSS_db

   The service console package NSS_db is updated to version
   nss_db-2.2-35.4.el5_5.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2010-0826 to this issue.

b. Service Console update for OpenLDAP

   The service console package OpenLDAP updated to version
   2.3.43-12.el5.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2009-3767 to this issue.

c. Service Console update for cURL

   The service console packages for cURL updated to version
   7.15.5-9.el5.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2010-0734 to this issue.

d. Service Console update for sudo

   The service console package sudo updated to version 1.7.2p1-7.el5_5.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2010-1646 to this issue.

e. Service Console update for OpenSSL, GnuTLS, NSS and NSPR

   Service Console updates for OpenSSL to version 097a-0.9.7a-9.el5_4.2
   and version 0.9.8e-12.el5_4.6, GnuTLS to version 1.4.1-3.el5_4.8,
   and NSS to version 3.12.6-1.3235.vmw and NSPR to version
   4.8.4-1.3235.vmw. These four updates are bundled together due to
   their mutual dependencies.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2009-3555, CVE-2009-2409, CVE-2009-3245
   and CVE-2010-0433 to the issues addressed in this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2010/000110.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/04");
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


init_esx_check(date:"2010-09-30");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201009401-SG",
    patch_updates : make_list("ESX400-201101401-SG", "ESX400-201103401-SG", "ESX400-201104401-SG", "ESX400-201110401-SG", "ESX400-201111201-SG", "ESX400-201203401-SG", "ESX400-201205401-SG", "ESX400-201206401-SG", "ESX400-201209401-SG", "ESX400-201302401-SG", "ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201009407-SG",
    patch_updates : make_list("ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201009408-SG",
    patch_updates : make_list("ESX400-201101402-SG", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201009409-SG",
    patch_updates : make_list("ESX400-201203403-SG", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201009410-SG",
    patch_updates : make_list("ESX400-201101404-SG", "ESX400-201305402-SG", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201010402-SG",
    patch_updates : make_list("ESX40-TO-ESX41UPDATE01", "ESX410-201110204-SG", "ESX410-201110214-SG", "ESX410-201201404-SG", "ESX410-201208103-SG", "ESX410-201208106-SG", "ESX410-201211405-SG", "ESX410-201307402-SG", "ESX410-201307403-SG", "ESX410-201307404-SG", "ESX410-201312403-SG", "ESX410-Update01", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201010404-SG",
    patch_updates : make_list("ESX40-TO-ESX41UPDATE01", "ESX410-Update01", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201010410-SG",
    patch_updates : make_list("ESX40-TO-ESX41UPDATE01", "ESX410-201201402-SG", "ESX410-Update01", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
