#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90893);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/04/24 19:17:53 $");

  script_cve_id(
    "CVE-2016-1362",
    "CVE-2016-1363",
    "CVE-2016-1364"
  );
  script_bugtraq_id(
    86761,
    86770,
    86772
  );
  script_osvdb_id(
    137379,
    137381,
    137382
  );
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160420-bdos");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160420-htrd");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160420-wlc");
  script_xref(name:"CISCO-BUG-ID", value:"CSCun86747");
  script_xref(name:"CISCO-BUG-ID", value:"CSCur66908");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus25617");

  script_name(english:"Cisco Wireless LAN Controller Multiple Vulnerabilities");
  script_summary(english:"Checks the WLC version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing vendor-supplied security patches.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Wireless LAN
Controller (WLC) device is affected by multiple vulnerabilities :

  - A denial of service vulnerability exists within the
    web-based device management interface of AireOS due to
    the presence of unsupported URLs that are not generally
    accessible from and supported by the management
    interface. An unauthenticated, remote attacker can
    exploit this, via a crafted HTTP request to one of these
    URLs, to cause the device to reload. (CVE-2016-1362)

  - A buffer overflow condition exists in the redirection
    functionality due to a failure to properly validate
    user-supplied input when handling HTTP requests. An
    unauthenticated, remote attacker can exploit this, via a
    crafted request, to execute arbitrary code.
    (CVE-2016-1363)

  - A denial of service vulnerability exists due to improper
    handling of crafted Bonjour traffic, which allows an
    unauthenticated, remote attacker to cause the device
    to reload. (CVE-2016-1364)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160420-bdos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48a85f12");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160420-wlc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b44f6138");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160420-htrd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?485267ab");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2016/Apr/114");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patches referenced in Cisco Bug ID CSCun86747,
CSCur66908, and CSCus25617.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

version = get_kb_item_or_exit("Host/Cisco/WLC/Version");
fix = "";

# 4.x - 6.x are vuln
if (version =~ "^[456]($|[^0-9])")
  fix = "Upgrade to 8.0(132.0) or later.";


# 7.0.x - 7.3.x are vuln
if (version =~ "^7\.[0-3]($|[^0-9])")
  fix = "Upgrade to 8.0(132.0) or later.";

# 7.4.x < 7.4.140.0
if (
  version == "7.4" ||
  version =~ "^7\.4\.([0-9]|[0-9][0-9]|1[0-3][0-9])($|[^0-9])"
)
  fix = "Upgrade to 7.4(140.0) or later.";

# 7.5.x and 7.6.x are vuln
if (version =~ "^7\.[56]($|[^0-9])")
  fix = "Upgrade to 8.0(132.0) or later.";

# 8.x < 8.0.115.0
if (
  version == "8.0" ||
  version =~ "^8\.0\.([0-9]|[0-9][0-9]|10[0-9]|11[0-4])($|[^0-9])"
)
  fix = "Upgrade to 8.0(115.0) or later.";

if (!fix) audit(AUDIT_HOST_NOT, "affected");

security_report_v4(
  port:0,
  severity:SECURITY_HOLE,
  extra:
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n'
);
