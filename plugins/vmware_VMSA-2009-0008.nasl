#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2009-0008. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(40393);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id("CVE-2009-0844", "CVE-2009-0845", "CVE-2009-0846");
  script_bugtraq_id(34257, 34409);
  script_osvdb_id(52963, 53383, 53384);
  script_xref(name:"VMSA", value:"2009-0008");

  script_name(english:"VMSA-2009-0008 : ESX Service Console update for krb5");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. Service Console package krb5 update

   Kerberos is a network authentication protocol. It is designed to
   provide strong authentication for client/server applications by
   using secret-key cryptography.

   An input validation flaw in the asn1_decode_generaltime function in
   MIT Kerberos 5 before 1.6.4 allows remote attackers to cause a
   denial of service or possibly execute arbitrary code via vectors
   involving an invalid DER encoding that triggers a free of an
   uninitialized pointer.

   A remote attacker could use this flaw to crash a network service
   using the MIT Kerberos library, such as kadmind or krb5kdc, by
   causing it to dereference or free an uninitialized pointer or,
   possibly, execute arbitrary code with the privileges of the user
   running the service.

   NOTE: ESX by default is unaffected by this issue, the daemons
   kadmind and krb5kdc are not installed in ESX.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2009-0846 to this issue.

   In addition the ESX 4.0 Service Console krb5 package was also
   updated for CVE-2009-0845, and CVE-2009-0844 and RHBA-2009-0135.

   MIT Kerberos versions 5 1.5 through 1.6.3 might allow remote
   attackers to cause a denial of service by using invalid
   ContextFlags data in the reqFlags field in a negTokenInit token.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-0845 to this issue.

   MIT Kerberos 5 before version 1.6.4 might allow remote attackers to
   cause a denial of service or possibly execute arbitrary code by
   using vectors involving an invalid DER encoding that triggers a
   free of an uninitialized pointer.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2009-0846 to this issue.

   For ESX 4.0, 3.5, 3.0.3 the Service Console package pam_krb5 has
   also been upgraded.  For details on the non-security issues that
   this upgrade addresses, refer to the respective KB article listed
   in section 4 below."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2009/000063.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/27");
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


init_esx_check(date:"2009-06-30");
flag = 0;


if (esx_check(ver:"ESX 2.5.5", patch:"14")) flag++;

if (
  esx_check(
    ver           : "ESX 3.0.3",
    patch         : "ESX303-200908403-SG",
    patch_updates : make_list("ESX303-201102401-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200906407-SG",
    patch_updates : make_list("ESX350-201008411-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.0.0",
    patch         : "ESX400-200906405-SG",
    patch_updates : make_list("ESX400-201005406-SG", "ESX400-201009403-SG", "ESX400-201110403-SG", "ESX400-201203407-SG", "ESX400-Update01a", "ESX400-Update02", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
