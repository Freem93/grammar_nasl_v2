#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86916);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:15:08 $");

  script_cve_id(
    "CVE-2015-6292",
    "CVE-2015-6293",
    "CVE-2015-6298",
    "CVE-2015-6321"
  );
  script_osvdb_id(
    129890,
    129891,
    129892,
    129893
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCzv95795");
  script_xref(name:"IAVA", value:"2015-A-0282");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus83445");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus10922");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur39155");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu29304");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151104-aos");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151104-wsa");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151104-wsa1");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20151104-wsa2");

  script_name(english:"Cisco Web Security Appliance Multiple Vulnerabilities");
  script_summary(english:"Checks the WSA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote security appliance is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Web Security
Appliance (WSA) running on the remote host is affected by the
following vulnerabilities :

  - A denial of service vulnerability exists due to a
    failure to free memory objects when retrieving data from
    the proxy server to terminate a TCP connection. An
    unauthenticated, remote attacker can exploit this, by
    opening a large number of proxy connections, to cause
    exhaustion of memory, resulting in the WSA to stop
    passing traffic. (CVE-2015-6292)

  - A denial of service vulnerability exists due to a
    failure to free memory when a file range is requested.
    An unauthenticated, remote attacker can exploit this, by
    opening multiple connections that request file ranges,
    to cause exhaustion of memory, resulting in the WSA to
    stop passing traffic. (CVE-2015-6293)

  - A flaw exists in the certificate generation process due
    to improper validation of parameters passed to the
    affected scripts of the web interface. An authenticated,
    remote attacker can exploit this, via crafted arguments
    to the parameters, to execute arbitrary commands on the
    system with root level privileges. (CVE-2015-6298)

  - A denial of service vulnerability exists due to improper
    handling of TCP packets sent at a high rate. An
    unauthenticated, remote attacker can exploit this to
    exhaust all available memory, preventing any more
    TCP connections from being accepted. (CVE-2015-6321)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151104-aos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e38ff5dd");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151104-wsa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa504ae8");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151104-wsa1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?619ea933");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151104-wsa2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?747a653a");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant updates referenced in Cisco Security Advisories
cisco-sa-20151104-aos, cisco-sa-20151104-wsa, cisco-sa-20151104-wsa1,
and cisco-sa-20151104-wsa2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Web Security Appliance/Version');

if (ver =~ "^[0-6]\." || ver =~ "^7\.[0-6]\.") # Prior to 7.7
  display_fix = '7.7.0-761';
else if (ver =~ "^7\.7\.")
  display_fix = '7.7.0-761';
else if (ver =~ "^8\.0\.")
  display_fix = '8.0.8-113';
else if (ver =~ "^8\.1\.")
  display_fix = '8.5.3-051';
else if (ver =~ "^8\.5\.")
  display_fix = '8.5.3-051';
else if (ver =~ "^8\.6\.")
  display_fix = '8.7.0-171';
else if (ver =~ "^8\.7\.")
  display_fix = '8.7.0-171';
else if (ver =~ "^8\.8\.")
  display_fix = '8.8.0-085';
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco WSA', display_ver);

fix = str_replace(string:display_fix, find:'-', replace:'.');

if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + display_ver +
      '\n  Fixed version     : ' + display_fix +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco WSA', display_ver);
