#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72604);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/02/20 20:30:32 $");

  script_cve_id("CVE-2010-3130");
  script_bugtraq_id(42729);
  script_osvdb_id(67479);
  script_xref(name:"EDB-ID", value:"14764");

  script_name(english:"Snagit DLL Preloading Arbitrary Code Execution");
  script_summary(english:"Checks Snagit version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A screen capture and sharing tool installed on the remote host is
affected by a DLL preloading vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Snagit installed on the remote Windows host has a DLL
preloading vulnerability.  An attacker can execute arbitrary code by
tricking a user into opening a Snagit file (.snag, .snagprof, or
.snagcc) from an attacker-controlled location such as a network share."
  );
  # https://support.techsmith.com/entries/22866171-Snagit-DLL-Preloading-Vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?965c0416");
  script_set_attribute(attribute:"see_also", value:"http://www.techsmith.com/snagit-version-history.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Snagit 11.1.0 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:techsmith:snagit");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("snagit_installed.nbin");
  script_require_keys("SMB/Snagit/Installed");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "Snagit";
kb_base = "SMB/Snagit/";

version = get_kb_item_or_exit(kb_base + "Version");
path = get_kb_item_or_exit(kb_base + "Path");

if (version !~ "^1[01]\.") audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

fix = "11.1.0";
if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0) audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
