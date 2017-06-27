#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86951);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:15:08 $");

  script_cve_id("CVE-2015-6366");
  script_bugtraq_id(77569);
  script_osvdb_id(130186);
  script_xref(name:"CISCO-BUG-ID", value:"CSCur01042");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151112-ios2");

  script_name(english:"Cisco IOS Tunnel Interfaces Security Bypass");
  script_summary(english:"Checks the version of Cisco IOS");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is affected by a security bypass vulnerability
due to physical-interface ACLs superseding tunnel-interface ACLs. An
authenticated, remote attacker connected to a tunnel interface can
exploit this to bypass intended network-traffic restrictions.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151112-ios2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfef67f9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCur01042.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"TRUE");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

version = get_kb_item_or_exit('Host/Cisco/IOS/Version');
flag = 0;

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version == "15.2(4)M6") flag++;
if (version == "15.4(3)S")  flag++;

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCur01042' +
    '\n  Installed release : ' + version +
    '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(port:0);
}
else audit(AUDIT_HOST_NOT, "affected");
