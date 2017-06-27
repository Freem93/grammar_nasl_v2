#TRUSTED 8e2899c3fcba12d7f727644693a95c74d2effbc7229302e4ef1141944c6735c92deb64235e15b9914022b22e22445d6fd0159f009a2eb80152c482386fcf5782b997912072dd345ac7bba2eda44eb55774da70f3ea54995e968dd18cb442066352ec4e84651d3f66b81f5fdcbe5af78c40c4ff5ee5cd2e92d8f46d4fdb4b6940d4a288e105d85c21657fc0cff8340e1a4ae5a5c2abf2fda2911c0ef403ab1decce271220dd82e8dd52ac5467e54338bee0dc82558d67818a1045cba0c8c21bd46a3cc25135ce6e09f59399d95d8762aac1609f84aab5540273213fd3448aeb896171143790c761c20ef8d03b189352185c48d88a5cdc9ae32945261a3d015489171af883ab187290c5072fb3fc21cfcb5d14df118e573a404f5f5a167789a2dadf2fa53d82b4b188fafc305cf88f14d6a6e149b8c09e1231c5405030bd98b72d6fedf3ff3e3c7cfbfa5fb4a068decec8411deb3d1e9b5ff8acf525f24ef80a37490c4b2e794d7bdc9a77daec06e4e6cbbb1ecabec1a34d1926c258b0af55ac51d28d4f17f90fca5455d047a34be26ff822ad0dec4c1455215128bc0a247f81744d9d68d6a9f742cc894fd6c2bac2df6399c0841abc418200dc0545644c4ba72d68071ba932569fea6df5a3b3c27dced7393cec5590a11dbee413af526229eff18a4dc4b2eb17fee4fdf55ecc4b50cf84b049030f89107cb089d21908cbe32f70
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
  script_id(71433);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/01/15");

  script_cve_id("CVE-2008-0960");
  script_bugtraq_id(29623);
  script_osvdb_id(46086);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsf30109");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20080610-snmpv3");
  script_xref(name:"CERT", value:"878044");
  script_xref(name:"EDB-ID", value:"5790");

  script_name(english:"SNMP Version 3 Authentication Vulnerabilities (cisco-sa-20080610-snmpv3)");
  script_summary(english:"Checks the IOS XR version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple Cisco products contain either of two authentication
vulnerabilities in the Simple Network Management Protocol version 3
(SNMPv3) feature.  These vulnerabilities can be exploited when
processing a malformed SNMPv3 message.  The vulnerabilities could allow
the disclosure of network information or may enable an attacker to
perform configuration changes to vulnerable devices.  The SNMP server is
an optional service that is disabled by default in Cisco products.  Only
SNMPv3 is impacted by these vulnerabilities.  Workarounds are available
for mitigating the impact of the vulnerabilities described in this
document.  Note: SNMP versions 1, 2 and 2c are not impacted by these
vulnerabilities.  The United States Computer Emergency Response Team
(US-CERT) has assigned Vulnerability Note VU#878044."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20080610-snmpv3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de728022");
  script_set_attribute(
    attribute:"solution", 
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080610-snmpv3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
report = "";
override = 0;

cbi = "CSCsf30109";

version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
if ((cisco_gen_ver_compare(a:version, b:"3.3.1") >= 0) && (cisco_gen_ver_compare(a:version, b:"3.3.2") == -1)) flag ++;
fixed_ver = "3.3.2.6";

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_snmp_group", "show snmp group");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"[Ss]ecurity\s+[Mm]odel:usm", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report =
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed Release : ' + version +
    '\n    Fixed Release     : ' + fixed_ver + '\n';

  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);

}
else audit(AUDIT_HOST_NOT, "affected");
