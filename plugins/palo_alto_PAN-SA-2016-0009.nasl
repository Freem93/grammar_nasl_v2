#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92942);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/05 16:04:17 $");

  script_cve_id("CVE-2016-2219");
  script_bugtraq_id(91461, 91468);
  script_osvdb_id(140604, 140630);
  script_xref(name:"TRA", value:"TRA-2016-19");

  script_name(english:"Palo Alto Networks PAN-OS 7.0.x < 7.0.8 Multiple Vulnerabilities (PAN-SA-2016-0008 / PAN-SA-2016-0009)");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Palo Alto Networks PAN-OS running on the remote host is
7.0.x prior to 7.0.8. It is, therefore, affected by the following
vulnerabilities :

  - A denial of service vulnerability exists in the API
    hosted on the management interface, specifically in the
    panUserLogin() function within panmodule.so, due to
    improper validation of user-supplied input to the
    'username' and 'password' parameters. An
    unauthenticated, remote attacker can exploit this, via a
    crafted request, to cause the process to terminate.
    (PAN-SA-2016-0008)

  - A cross-site scripting (XSS) vulnerability exists in the
    Application Command Center (ACC) due to improper
    sanitization of user-supplied input before returning it
    to users. An authenticated, remote attacker can exploit
    this, via a specially crafted request, to execute
    arbitrary script code in a user's browser session.
    (PAN-SA-2016-0009, CVE-2016-2219)");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/41");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/42");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/security/research/tra-2016-19");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 7.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

# Ensure sufficient granularity.
if (version !~ "^7.0.")
  audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);

fix = '7.0.8';

# Compare version to fix and report as needed.
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Installed version : ' + full_version +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(port:0, severity:SECURITY_WARNING, xss:TRUE, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
