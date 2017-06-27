#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90429);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/03/07 17:25:25 $");

  script_cve_id(
    "CVE-2016-82008",
    "CVE-2016-82009",
    "CVE-2016-82010",
    "CVE-2016-82011"
  );
  script_osvdb_id(
    136588,
    136589,
    136590,
    136591,
    136592
  );

  script_name(english:"Tenable SecurityCenter 5.2.x / 5.3.x < 5.3.1 Multiple Vulnerabilities (TNS-2016-07)");
  script_summary(english:"Checks the SecurityCenter version.");

  script_set_attribute(attribute:"synopsis", value:
"The application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Tenable SecurityCenter application
installed on the remote host is 5.2.x or 5.3.x prior to 5.3.1. It is,
therefore, affected by multiple vulnerabilities :

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist due to a failure to properly validate input before
    returning it to users. A remote attacker can exploit
    these, via a crafted request, to execute arbitrary
    script code in a user's browser session.
    (CVE-2016-82008, CVE-2016-82009, CVE-2016-82010)

  - An unspecified flaw exists that allows an authenticated,
    remote  attacker to disclose the installation path of
    the application. (CVE-2016-82011)

  - A flaw exists in Apache Felix due to a failure to use
    the HTTPOnly or Secure attribute for authentication
    cookies. An unauthenticated, remote attacker can exploit
    this to more easily disclose sensitive information.
    (VulnDB 136592)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/security/tns-2016-07");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable SecurityCenter version 5.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_keys("Host/SecurityCenter/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/SecurityCenter/Version");
fix = "5.3.1";

if (version =~ "^5\.(2|3\.0)(\.|$)")
{
  items = make_array("Installed version", version,
                     "Fixed version", fix
                    );

  order = make_list("Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(severity:SECURITY_WARNING, port:0, extra:report, xss:TRUE);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, 'SecurityCenter', version);
