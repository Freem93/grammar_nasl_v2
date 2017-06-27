#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76463);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"HP", value:"emr_na-c04268240");
  script_xref(name:"HP", value:"HPSBMU03029");
  script_xref(name:"HP", value:"SSRT101543");

  script_name(english:"HP Insight Control Server Migration 7.3.0 and 7.3.1 OpenSSL Heartbeat Information Disclosure (Heartbleed)");
  script_summary(english:"Checks HP Insight Control Server Migration version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has migration software installed that is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the HP Insight Control Server Migration
install on the remote Windows host includes a bundled copy of OpenSSL
that is affected by an information disclosure vulnerability. A remote
attacker could read the contents of up to 64KB of server memory,
potentially exposing passwords, private keys, and other sensitive
data.");
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04268240
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d1a2602");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:
"Update to HP Insight Control Server Migration 7.3.2, which is included
with the HP Insight Management 7.0.3a incremental update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:server_migration_pack_universal_edition");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:insight_control_server_migration");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_insight_control_server_migration_installed.nbin");
  script_require_keys("installed_sw/HP Insight Control Server Migration");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "HP Insight Control Server Migration";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

# Only 1 install of the server is possible.
install = get_installs(app_name:app_name);
if (install[0] == IF_NOT_FOUND) audit(AUDIT_NOT_INST, app_name);
install = install[1][0];

version = install['version'];
path = install['path'];

# Determine fix if affected branch.
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_APP_VER, app_name);

if (version =~ "^7\.3(\.0|$)" || version == "7.3.1")
{
  fix = "7.3.2";

  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
