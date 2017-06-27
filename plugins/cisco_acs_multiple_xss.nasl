#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69853);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_cve_id("CVE-2013-3423", "CVE-2013-3424");
  script_bugtraq_id(61173, 61175);
  script_osvdb_id(95199, 95200);
  script_xref(name:"CISCO-BUG-ID", value:"CSCud75174");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud75177");

  script_name(english:"Cisco Secure Access Control System (ACS) Multiple Vulnerabilities");
  script_summary(english:"Checks version of Cisco ACS");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Secure Access Control System installed on the
remote host is potentially affected by multiple vulnerabilities :

  - An unspecified cross-site scripting vulnerability exists
    in the web interface. (CVE-2013-3423)

  - An unspecified cross-site request forgery vulnerability
    exists in the Admin/View Page. (CVE-2013-3424)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-3423
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96d3f981");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-3424
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4808d13e");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=30076");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Access Control System 5.3(0.40.9) / 5.4(0.46.3) or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:secure_access_control_system");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ACS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Make sure local checks are enabled for ACS
get_kb_item_or_exit("Host/Cisco/ACS");
version = get_kb_item_or_exit('Host/OS/showver');

# Make sure it is Cisco ACS'
if ('Cisco ACS' >!< version) audit(AUDIT_HOST_NOT, 'Cisco ACS');

# Make sure we can get the version number
version = version - 'Cisco ACS ';
if (version !~ '^[0-9\\.]+') exit(1, 'Failed to extract the version of Cisco ACS');

# Fixed in
fix = '';
if (version =~ '^5\\.3\\.0\\.40\\.[0-8][^0-9]') fix = '5.3.0.40.9';
else if (version =~ '^5\\.4\\.0\\.46\\.[0-2][^0-9]') fix = '5.4.0.46.3';

if (fix)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  set_kb_item(name:'www/0/XSRF', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(port:0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Cisco Access Control System', version);
