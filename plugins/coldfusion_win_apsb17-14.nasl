#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99669);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/27 15:16:32 $");

  script_cve_id("CVE-2017-3008", "CVE-2017-3066");
  script_bugtraq_id(98002, 98003);
  script_osvdb_id(156286, 156287);
  script_xref(name:"IAVA", value:"2017-A-0122");

  script_name(english:"Adobe ColdFusion 10.x < 10u23 / 11.x < 11u12 / 2016.x < 2016u4 Multiple Vulnerabilities (APSB17-14)");
  script_summary(english:"Checks the hotfix files.");

  script_set_attribute(attribute:"synopsis", value:
"A web-based application running on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe ColdFusion running on the remote Windows host is
10.x prior to update 23, 11.x prior to update 12, 2016.x prior to
update 4. It is, therefore, affected by multiple vulnerabilities :

  - A reflected cross-site scripting (XSS) vulnerability
    exists due to improper validation of user-supplied
    input. An unauthenticated, remote attacker can exploit
    this, via a specially crafted request, to execute
    arbitrary script code in user's browser session.
    (CVE-2017-3008)

  - A Java deserialization flaw exists in the Apache BlazeDS
    library that allows an unauthenticated, remote attacker
    to execute arbitrary code. (CVE-2017-3066)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/coldfusion/apsb17-14.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe ColdFusion version 10 update 23 / 11 update 12 / 2016
update 4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_win_local_detect.nasl");
  script_require_keys("SMB/coldfusion/instance");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("coldfusion_win.inc");
include("global_settings.inc");
include("misc_func.inc");

versions = make_list('10.0.0', '11.0.0', '2016.0.0');
instances = get_coldfusion_instances(versions); # this exits if it fails

# Check the hotfixes and cumulative hotfixes installed for each
# instance of ColdFusion.
info = NULL;
instance_info = make_list();

foreach name (keys(instances))
{
  info = NULL;
  ver = instances[name];

  if (ver == "10.0.0")
  {
    # CF10 uses an installer for updates so it is less likely (perhaps not possible) to only partially install a hotfix.
    # this means the plugin doesn't need to check for anything in the CFIDE directory, it just needs to check the CHF level
    info = check_jar_chf(name, 23);
  }
  else if (ver == "11.0.0")
  {
    info = check_jar_chf(name, 12);
  }

 else if (ver == "2016.0.0")
  {
    info = check_jar_chf(name, 4);
  }

  if (!isnull(info))
    instance_info = make_list(instance_info, info);
}

if (max_index(instance_info) == 0)
  exit(0, "No vulnerable instances of Adobe ColdFusion were detected.");

port = get_kb_item("SMB/transport");
if (!port)
  port = 445;

report =
  '\n' + 'Nessus detected the following unpatched instances :' +
  '\n' + join(instance_info, sep:'\n') +
  '\n';

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE, xss:TRUE);
exit(0);
