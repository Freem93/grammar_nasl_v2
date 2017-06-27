#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2008-0017. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(40384);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id("CVE-2008-0960", "CVE-2008-2327", "CVE-2008-3281", "CVE-2008-3529");
  script_bugtraq_id(29623, 30783, 30832);
  script_osvdb_id(46060, 47636, 47795, 48158, 55248);
  script_xref(name:"VMSA", value:"2008-0017");

  script_name(english:"VMSA-2008-0017 : Updated ESX packages for libxml2, ucd-snmp, libtiff");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. Updated ESX Service Console package libxml2

   A denial of service flaw was found in the way libxml2 processes
   certain content. If an application that is linked against
   libxml2 processes malformed XML content, the XML content might
   cause the application to stop responding.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2008-3281 to this issue.

   Additionally the following was also fixed, but was missing in the
   security advisory.

   A heap-based buffer overflow flaw was found in the way libxml2
   handled long XML entity names. If an application linked against
   libxml2 processed untrusted malformed XML content, it could cause
   the application to crash or, possibly, execute arbitrary code.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2008-3529 to this issue.

b. Updated ESX Service Console package ucd-snmp

   A flaw was found in the way ucd-snmp checks an SNMPv3 packet's
   Keyed-Hash Message Authentication Code. An attacker could use
   this flaw to spoof an authenticated SNMPv3 packet.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2008-0960 to this issue.

c. Updated third-party library libtiff

   Multiple uses of uninitialized values were discovered in libtiff's
   Lempel-Ziv-Welch (LZW) compression algorithm decoder. An attacker
   could create a carefully crafted LZW-encoded TIFF file that would
   cause an application linked with libtiff to crash or, possibly,
   execute arbitrary code.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2008-2327 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2008/000047.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.5.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:2.5.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/31");
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


init_esx_check(date:"2008-10-31");
flag = 0;


if (esx_check(ver:"ESX 2.5.4", patch:"21")) flag++;

if (esx_check(ver:"ESX 2.5.5", patch:"10")) flag++;

if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1006968")) flag++;

if (
  esx_check(
    ver           : "ESX 3.0.3",
    patch         : "ESX303-200810503-SG",
    patch_updates : make_list("ESX303-201002204-UG", "ESX303-Update01")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
