#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2008-0007. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(40377);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id("CVE-2006-7228", "CVE-2007-1660", "CVE-2007-5846", "CVE-2008-0003");
  script_bugtraq_id(26378, 26462, 26727, 27172);
  script_osvdb_id(38904, 40082, 40754, 40764);
  script_xref(name:"VMSA", value:"2008-0007");

  script_name(english:"VMSA-2008-0007 : Moderate Updated Service Console packages pcre, net-snmp, and OpenPegasus");
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
"a. Updated pcre Service Console package addresses several security issues

The pcre package contains the Perl-Compatible Regular Expression library.
pcre is used by various Service Console utilities.

Several security issues were discovered in the way PCRE handles regular
expressions. If an application linked against PCRE parsed a malicious
regular expression, it may have been possible to run arbitrary code as
the user running the application.

VMware would like to thank Ludwig Nussel for reporting these issues.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the names CVE-2006-7228 and CVE-2007-1660 to these issues.

b. Updated net-snmp Service Console package addresses denial of service

net-snmp is an implementation of the Simple Network Management
Protocol (SNMP).  SNMP is used by network management systems to
monitor hosts.  By default ESX has this service enabled and its ports
open on the ESX firewall.

A flaw was discovered in the way net-snmp handled certain requests. A
remote attacker who can connect to the snmpd UDP port could send a
malicious packet causing snmpd to crash, resulting in a denial of
service.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2007-5846 to this issue.

c. Updated OpenPegasus Service Console package fixes overflow condition

OpenPegasus is a CIM (Common Information Model) and Web-Based Enterprise
Management (WBEM) broker.  These protocols are used by network management
systems to monitor and control hosts.  By default ESX has this service
enabled and its ports open on the ESX firewall.

A flaw was discovered in the OpenPegasus CIM management server that
might allow remote attackers to execute arbitrary code.  OpenPegasus
when compiled to use PAM and without PEGASUS_USE_PAM_STANDALONE_PROC
defined, has a stack-based buffer overflow condition.

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2008-0003 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2008/000019.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/04");
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


init_esx_check(date:"2008-04-15");
flag = 0;


if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1004184")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1004187")) flag++;
if (esx_check(ver:"ESX 3.0.1", patch:"ESX-1004188")) flag++;

if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1004213")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1004217")) flag++;
if (esx_check(ver:"ESX 3.0.2", patch:"ESX-1004218")) flag++;

if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200803201-UG",
    patch_updates : make_list("ESX350-200911210-UG", "ESX350-200912406-BG", "ESX350-201006409-BG", "ESX350-201105403-BG", "ESX350-Update01", "ESX350-Update02", "ESX350-Update03", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-200803214-UG",
    patch_updates : make_list("ESX350-Update01", "ESX350-Update02", "ESX350-Update03", "ESX350-Update04", "ESX350-Update05", "ESX350-Update05a")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
