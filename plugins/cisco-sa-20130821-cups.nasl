#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69553);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/12 21:59:44 $");

  script_cve_id("CVE-2013-3453");
  script_bugtraq_id(61917);
  script_osvdb_id(96484);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130821-cup");
  script_xref(name:"IAVB", value:"2013-B-0094");

  script_name(english:"Cisco Unified Communications Manager IM and Presence Server DoS (cisco-sa-20130821-cup)");
  script_summary(english:"Checks CUPS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the version of Cisco Unified
Communications Manager IM and Presence Server installed on the remote
host has a denial of service vulnerability.  An unauthenticated, remote
attacker could exploit this by creating a large number of connections to
the SIP ports (TCP 5060, and 5061) on the device resulting in excessive
memory consumption.  The device must be restarted to fix the denial of
service condition."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130821-cup
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50c9459e");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Cisco Unified Presence Server 8.6(5)SU1 / 9.1(2) or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_presence_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/UCOS/Cisco Unified Presence/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

display_version = get_kb_item_or_exit('Host/UCOS/Cisco Unified Presence/version');
match = eregmatch(string:display_version, pattern:'^([0-9.]+(?:-[0-9]+)?)($|[^0-9])');
if (isnull(match)) # this should not happen
  audit(AUDIT_FN_FAIL, 'eregmatch');
else
  version = match[1];

version = str_replace(string:version, find:"-", replace:".");

# the advisory says:
# Fixed versions are 8.6(5)SU1 for version 8.6,
# and 9.1(2) for version 9.0.x/9.1.x.

# 8.6.5SU1 is not available for download yet,
# but latest version available is 8.6(5), which
# is 8.6.5.10000-12

# 9.1(2) is not available for download yet,
# but latest version available is 9.1.1SU1, which
# is 9.1.1.31900-1
if (version =~ "^8\.6\." && ver_compare(ver:version, fix:'8.6.5.10000', strict:FALSE) <= 0)
  fix = '8.6.5.11900-1';
else if (version =~ "^9\.[01]\." && ver_compare(ver:version, fix:'9.1.1.31900', strict:FALSE) <= 0)
  fix = '9.1.2';
else
  audit(AUDIT_INST_VER_NOT_VULN, 'CUPS', display_version);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : ' + fix + '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
