#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59372);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/29 00:33:21 $");

  script_cve_id("CVE-2012-2752");
  script_bugtraq_id(53697);
  script_osvdb_id(82276);
  script_xref(name:"VMSA", value:"2012-0010");

  script_name(english:"VMware vMA Unspecified Library Local Privilege Escalation (VMSA-2012-0010)");
  script_summary(english:"Checks version of vmareleaseinfo package");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a
local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vMA installed on the remote SuSE Linux
Enterprise Server host is 4.x or 5.x earlier than 5.0.0.2.  As such,
it is potentially affected by a local privilege escalation
vulnerability due to the way library files are loaded.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0010.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2012/000177.html");
  script_set_attribute(attribute:"solution", value:"Update to vMA 5.0 Patch 2 (5.0.0.2) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vma");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}

include('global_settings.inc');
include('rpm.inc');
include('audit.inc');

if (!get_kb_item('Host/local_checks_enabled')) exit(0, 'Local checks are not enabled.');
if (!get_kb_item('Host/SuSE/release')) exit(0, 'The host is not running SuSE.');
list = get_kb_item('Host/SuSE/rpm-list');
if (isnull(list)) exit(1, 'Could not obtain the list of installed packages.');

my_rpm = parse_rpm_name(rpm:'vmareleaseinfo-5.0.0.2-1');
packages = egrep(pattern:'^vmareleaseinfo-[0-9]', string:list);
if (!packages) audit(AUDIT_NOT_INST, 'VMware vMA');

vuln = 0;
foreach package (split(packages, sep:'\n', keep:FALSE))
{
  item = parse_rpm_name(rpm:package);

  ver = split(item['version'], sep:'.');
  for (i=0; i < max_index(ver); i++)
    ver[i] = int(ver[i]);

  # nb: VMSA-2012-0010 lists vMA 4.x and 5.x as affected.
  if (
    ver[0] == 4 ||
    (ver[0] == 5 && ver[1] == 0 && ver[2] == 0 && ver[3] < 2)
  )
  {
    vuln++;
    rpm_report_add(package:package, reference:'vmareleaseinfo-5.0.0.2-1');
  }
}

if (vuln)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_INST_VER_NOT_VULN, 'VMware vMA');
