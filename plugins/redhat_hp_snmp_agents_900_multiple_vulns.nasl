#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59189);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/02 14:37:09 $");

  script_cve_id("CVE-2012-2001", "CVE-2012-2002");
  script_bugtraq_id(53338, 53340);
  script_osvdb_id(81696, 81697);

  script_name(english:"HP SNMP Agents < 9.0.0 Multiple Vulnerabilities (HPSBMU02771 SSRT100558) (Red Hat)");
  script_summary(english:"Checks version of hp-snmp-agents package");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the HP SNMP Agents package installed on the remote Red
Hat Enterprise Linux host is earlier than 9.0.0 and, as such,
potentially affected by the following vulnerabilities :

  - An unspecified cross-site scripting vulnerability 
    exists. (CVE-2012-2001)

  - An unspecified URL redirection vulnerability exists.
    (CVE-2012-2002)");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5adc03b");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/May/6");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP SNMP Agents 9.0.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/18");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:snmp_agents_for_linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}

include("global_settings.inc");
include("rpm.inc");
include("audit.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/RedHat/release")) exit(0, "The host is not running Red Hat Enterprise Linux.");
list = get_kb_item('Host/RedHat/rpm-list');
if (isnull(list)) exit(1, "Could not obtain the list of installed packages.");

my_rpm = parse_rpm_name(rpm:'hp-snmp-agents-9.0.0.48-49');
package = egrep(pattern:'^hp-snmp-agents-[0-9]', string:list);
if (package == '') audit(AUDIT_NOT_INST, 'HP SNMP Agents');

vuln = 0;
lines = split(package, sep:'\n', keep:FALSE);
foreach package (lines)
{
  item = parse_rpm_name(rpm:package);

  ver = split(item['version'], sep:'.');
  for (i=0; i < max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (
    ver[0] < 9 ||
    (
      ver[0] == 9 && ver[1] == 0 && ver[2] == 0 && 
      (
        ver[3] < 48 ||
        ver[3] == 48 && int(item['release']) < 49
      )
    )
  )
  {
    vuln++;
    rpm_report_add(package:package, reference:'hp-snmp-agents-9.0.0.48-49');
  }
}

if (vuln)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_INST_VER_NOT_VULN, 'HP SNMP Agents');
