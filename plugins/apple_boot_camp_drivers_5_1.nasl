#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72602);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/02/20 20:20:00 $");

  script_cve_id("CVE-2014-1253");
  script_bugtraq_id(65522);
  script_osvdb_id(103267);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-02-11-1");

  script_name(english:"Apple Boot Camp Support Software < 5.1 AppleMNT.sys Driver PE Header Memory Corruption");
  script_summary(english:"Checks version in banner");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a driver affected by a local memory corruption
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apple Boot Camp Support Software installed on the
remote host is a version prior to 5.1. As such, the AppleMNT.sys
driver included in it reportedly has a bounds checking issue that can
be triggered when parsing a Portable Executable (PE) file with a
malformed header. A local attacker may be able to leverage this to
corrupt kernel memory resulting in a system crash or arbitrary code
execution with elevated privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6126");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/531045/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Boot Camp Support Software 5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:boot_camp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("apple_boot_camp_drivers_installed.nbin");
  script_require_keys("SMB/Boot_Camp/Installed");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = 'Apple Boot Camp Support Software';
kb_base = "SMB/Boot_Camp/";

get_kb_item_or_exit(kb_base+"Installed");
version = get_kb_item_or_exit(kb_base+"Version_UI", exit_code:1);

fixed_version = '5.1';
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port:port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
