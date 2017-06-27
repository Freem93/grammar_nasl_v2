#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79271);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/19 17:45:33 $");

  script_cve_id("CVE-2011-4862");
  script_bugtraq_id(51182);
  script_osvdb_id(78020);
  script_xref(name:"EDB-ID", value:"18280");
  script_xref(name:"CISCO-BUG-ID", value:"CSCzv32432");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120126-ironport");

  script_name(english:"Cisco Email Security Appliance Telnet Remote Code Execution (cisco-sa-20120126-ironport)");
  script_summary(english:"Checks the ESA version.");

  script_set_attribute(attribute:"synopsis", value:"The remote security appliance is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of AsyncOS running
on the remote Cisco Email Security Appliance (ESA) is affected by a
remote code execution vulnerability due to a buffer overflow condition
in the telnet component.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120126-ironport
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?493371b6");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCzv32432");
  script_set_attribute(attribute:"see_also", value:"https://www.freebsd.org/security/advisories/FreeBSD-SA-11:08.telnetd.asc");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant update referenced in Cisco Security Advisory
cisco-sa-20120126-ironport.

Alternatively, as a workaround, the vendor notes that Telnet services
can be disabled on the device.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-760");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux BSD-derived Telnet Service Encryption Key ID Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:email_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Email Security Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Email Security Appliance/Version');

# If not paranoid, check if telnet is detected first.
# get_service() may fork; don't use.
if (report_paranoia < 2) get_kb_list_or_exit("Services/telnet");

# Affected/Fixed Cisco AsyncOS Software for Cisco ESA :
# 7.1 and prior - 7.1.5-101
# 7.3 - 7.3.1-101
# 7.5 - 7.5.1-102
# 7.6 - 7.6.1-022
# 8.0 - Not Affected
# 8.5 - Not Affected
# 8.6 - Not Affected
if (ver =~ "^[0-6]\." || ver =~ "^7\.[01]\.")
  display_fix = '7.1.5-101';
else if (ver =~ "^7\.3\.")
  display_fix = '7.3.1-101';
else if (ver =~ "^7\.5\.")
  display_fix = '7.5.1-102';
else if (ver =~ "^7\.6\.")
  display_fix = '7.6.1-022';
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ESA', display_ver);

fix = str_replace(string:display_fix, find:'-', replace:'.');

if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0) audit(AUDIT_INST_VER_NOT_VULN, 'Cisco ESA', display_ver);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + display_fix + 
    '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
