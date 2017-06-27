#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 6000) exit(0, "Nessus older than 6.0.x");

include("compat.inc");

if (description)
{
  script_id(95478);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/03/31 18:47:48 $");

  script_cve_id(
    "CVE-2016-9149",
    "CVE-2016-9150",
    "CVE-2016-9151"
  );
  script_bugtraq_id(
    94199,
    94399,
    94400,
    94401
  );
  script_osvdb_id(
    146509,
    147483,
    147484,
    147487
  );
  script_xref(name:"IAVA", value:"2016-A-0333");

  script_name(english:"Palo Alto Networks PAN-OS 5.0.x < 5.0.20 / 5.1.x < 5.1.13 / 6.0.x < 6.0.15 / 6.1.x < 6.1.15 / 7.0.x < 7.0.11 / 7.1.x < 7.1.6 Multiple Vulnerabilities (PAN-SA-2016-0033 / PAN-SA-2016-0034 / PAN-SA-2016-0035 / PAN-SA-2016-0037)");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Palo Alto Networks PAN-OS running on the remote host is
5.0.x prior to 5.0.20, 5.1.x prior to 5.1.13, 6.0.x prior to 6.0.15,
6.1.x prior to 6.1.15, 7.0.x prior to 7.0.11, or 7.1.x prior to 7.1.6.
It is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    Address Object Parsing functionality due to a failure to
    properly escape single quote characters. An
    unauthenticated, remote attacker can exploit this to
    inject XPath content, resulting in the disclosure of
    sensitive information. (CVE-2016-9149)

  - An off-by-one buffer overflow condition exists in the
    management web interface within the mprItoa() function.
    An unauthenticated, remote attacker can exploit this,
    via a specially crafted request, to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2016-9150)

  - An elevation of privilege vulnerability exists in
    /usr/local/bin/root_trace due to improper validation of
    the PYTHONPATH environment variable. A local attacker
    who has shell access can exploit this vulnerability, by
    manipulating environment variables, to execute code with
    root privileges. Note that this vulnerability exists
    because of an incomplete fix for CVE-2016-1712.
    (CVE-2016-9151)

  - A cross-site scripting (XSS) vulnerability exists in the
    Captive Portal due to improper validation of input
    before returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (VulnDB 146509)");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/66");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/67");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/68");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/70");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 5.0.20 / 5.1.13 /
6.0.15 / 6.1.15 / 7.0.11 / 7.1.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Palo Alto Networks PAN-OS";
version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Version");
full_version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Full_Version");
fix = NULL;

# Ensure sufficient granularity.
if (version !~ "^\d+\.\d+\.\d+") audit(AUDIT_VER_NOT_GRANULAR, app_name, full_version);

switch[=~] (version)
{
  case "^5\.0\.([0-9]|1[0-9])($|[^0-9])":
    fix = "5.0.20";
    break;
  case "^5\.1\.([0-9]|1[0-2])($|[^0-9])":
    fix = "5.1.13";
    break;
  case "^6\.0\.([0-9]|1[0-4])($|[^0-9])":
    fix = "6.0.15";
    break;
  case "^6\.1\.([0-9]|1[0-4])($|[^0-9])":
    fix = "6.1.15";
    break;
  case "^7\.0\.([0-9]|10)($|[^0-9])":
    fix = "7.0.11";
    break;
  case "^7\.1\.[0-5]($|[^0-9])":
    fix = "7.1.6";
    break;
  default:
    audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
}

report =
  '\n  Installed version : ' + full_version +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(severity:SECURITY_HOLE, extra:report, port:0, xss:TRUE);
