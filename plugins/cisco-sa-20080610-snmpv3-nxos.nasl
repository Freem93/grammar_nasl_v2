#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20080610-snmpv3.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(66697);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2008-0960");
  script_bugtraq_id(29623);
  script_osvdb_id(46086);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsf04754");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20080610-snmpv3");

  script_name(english:"SNMP Version 3 Authentication Bypass Vulnerabilities (cisco-sa-20080610-snmpv3)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple Cisco products contain either of two authentication
vulnerabilities in the Simple Network Management Protocol version 3
(SNMPv3) feature. These vulnerabilities can be exploited when
processing a malformed SNMPv3 message. These vulnerabilities could
allow the disclosure of network information or may enable an attacker
to perform configuration changes to vulnerable devices. The SNMP
server is an optional service that is disabled by default in Cisco
products. Only SNMPv3 is impacted by these vulnerabilities.
Workarounds are available for mitigating the impact of the
vulnerabilities described in this document. Note: SNMP versions 1, 2
and 2c are not impacted by these vulnerabilities. The United States
Computer Emergency Response Team (US-CERT) has assigned Vulnerability
Note VU#878044."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20080610-snmpv3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de728022"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080610-snmpv3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version");

  exit(0);
}



include("audit.inc");
include("cisco_func.inc");

flag = 0;

version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");
if ( version == '4.0' ) flag++;
if ( version == '4.0(1)' ) flag++;
if ( version == '4.0(1a)' ) flag++;

if (flag)
{
  security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
