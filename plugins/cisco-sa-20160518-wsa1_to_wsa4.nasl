#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91338);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/30 14:31:29 $");

  script_cve_id(
    "CVE-2016-1380",
    "CVE-2016-1381",
    "CVE-2016-1382",
    "CVE-2016-1383"
  );
  script_bugtraq_id(
    90742,
    90744,
    90746,
    90747
  );
  script_osvdb_id(
    138735,
    138736,
    138737,
    138738
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo12171");
  script_xref(name:"IAVB", value:"2016-B-0093");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw97270");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuu02529");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur28305");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160518-wsa1");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160518-wsa2");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160518-wsa3");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160518-wsa4");


  script_name(english:"Cisco Web Security Appliance Multiple DoS Vulnerabilities");
  script_summary(english:"Checks the WSA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote security appliance is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco Web Security
Appliance (WSA) running on the remote host is affected by the
following vulnerabilities :

  - A denial of service vulnerability exists in Cisco
    AsyncOS due to improper validation of packets when
    parsing HTTP POST requests. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    POST request, to cause the proxy process to become
    unresponsive, resulting in the WSA reloading.
    (CVE-2016-1380)

  - A denial of service vulnerability exists in Cisco
    AsyncOS in the cached file-range request functionality
    due to a failure to free memory when a file range for
    cached content is requested through the WSA. An
    unauthenticated, remote attacker can exploit this,
    via multiple connections that request file ranges,
    to cause the WSA to stop passing traffic because of
    memory exhaustion. (CVE-2016-1381)

  - A denial of service vulnerability exists in Cisco
    AsyncOS due to improper allocation of memory for HTTP
    headers and expected HTTP payloads. An unauthenticated,
    remote attacker can exploit this, via specially
    crafted HTTP requests, to cause the proxy process to
    unexpectedly reload. (CVE-2016-1382)

  - A denial of service vulnerability exists in Cisco
    AsyncOS due to a failure to free client and server
    connection memory and system file descriptors when a
    certain HTTP response code is received in the HTTP
    request. An unauthenticated, remote attacker can exploit
    this, via specially crafted HTTP requests, to cause the
    WSA to stop accepting new connections because of memory
    exhaustion. (CVE-2016-1383)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160518-wsa1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ce8631d");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160518-wsa2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?430ceb05");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160518-wsa3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?708f68af");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160518-wsa4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88b96b29");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant updates referenced in Cisco Security Advisories
cisco-sa-20160518-wsa1, cisco-sa-20160518-wsa2, cisco-sa-20160518-wsa3
and cisco-sa-20160518-wsa4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

display_ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion');
ver = get_kb_item_or_exit('Host/AsyncOS/Cisco Web Security Appliance/Version');

# Prior to 7.7
if (ver =~ "^[0-6]\." || ver =~ "^7\.[0-7]\.") display_fix = '9.0.1-162';
else if (ver =~ "^8\.0\.")     display_fix = '9.0.1-162';
else if (ver =~ "^8\.[5-8]\.") display_fix = '9.0.1-162';
else if (ver =~ "^9\.0\.")     display_fix = '9.0.1-162';
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco WSA', display_ver);

fix = str_replace(string:display_fix, find:'-', replace:'.');

if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco WSA', display_ver);

security_report_v4(
  port:0,
  severity:SECURITY_HOLE,
  extra:
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + display_fix +
    '\n'
);
