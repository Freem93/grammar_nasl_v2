#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22225);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/08/22 20:52:04 $");

  script_cve_id("CVE-2006-4201");
  script_bugtraq_id(19495);
  script_osvdb_id(27943);
  script_xref(name:"CERT", value:"673228");
  script_xref(name:"HP", value:"emr_na-c00742778");
  script_xref(name:"HP", value:"HPSBMA02138");
  script_xref(name:"HP", value:"SSRT061184");

  script_name(english:"HP Data Protector Backup Agent RCE");
  script_summary(english:"Checks for the Data Protector version.");

  script_set_attribute(attribute:"synopsis", value:
"The backup service running on the remote host is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP Data Protector running on the remote host is
affected by an unspecified flaw in the backup agent. An
unauthenticated, remote attacker can exploit this to execute arbitrary
code through the use of unauthorized backup commands.");
   # http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c00742778
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?331e9518");
  script_set_attribute(attribute:"solution", value:
"Apply the set of patches for HP Data Protector versions 5.10 and 5.50
as referenced in the HP advisory. Alternatively, if this service is
not needed, disable it or filter incoming traffic to this port.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value: "2006/08/10");
  script_set_attribute(attribute:"patch_publication_date", value: "2006/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value: "2006/08/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:storage_data_protector");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:data_protector");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_require_ports("Services/hp_openview_dataprotector", 5555);
  script_dependencies ("hp_data_protector_installed.nasl","hp_data_protector_installed_local.nasl");
  script_require_keys ("Services/data_protector/version", "Services/data_protector/build");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

version = get_kb_item_or_exit("Services/data_protector/version");
build = get_kb_item_or_exit("Services/data_protector/build");

port = get_kb_item("Services/hp_openview_dataprotector");
if (!port) port = 5555;

if ((version == "unknown") || (build == "unknown"))
  audit(AUDIT_UNKNOWN_APP_VER, "HP Data Protector");

vulnerable = FALSE;

if (version == "A.05.50")
{
 # unpatched version == build number
 if (egrep (pattern:"^[0-9]+", string:build))
   vulnerable = TRUE;

 # windows patch name (last vulnerable = DPWIN_00202)
 else if (egrep (pattern:"DPWIN_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"DPWIN_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build <= 202)
    vulnerable = TRUE;
 }
 # windows security patch (fixed in SSPNT550_110)
 else if (egrep (pattern:"SSPNT550_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"SSPNT550_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build < 110)
    vulnerable = TRUE;
 }
 # solaris security patch (fixed in SSPSOL550_035)
 else if (egrep (pattern:"SSPSOL550_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"SSPSOL550_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build < 35)
    vulnerable = TRUE;
 }
 # hp-ux security patch (fixed in SSPUX550_124)
 else if (egrep (pattern:"SSPUX550_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"SSPUX550_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build < 124)
    vulnerable = TRUE;
 }
}
else if (version == "A.05.10")
{
 # unpatched version == build number
 if (egrep (pattern:"^[0-9]+", string:build))
   vulnerable = TRUE;

 # windows patch name (last vulnerable = DPWIN_00172)
 if (egrep (pattern:"DPWIN_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"DPWIN_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build <= 172)
    vulnerable = TRUE;
 }
 # windows security patch (fixed in SSPNT510_080)
 else if (egrep (pattern:"SSPNT550_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"SSPNT550_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build < 80)
    vulnerable = TRUE;
 }
 # solaris security patch (fixed in SSPSOL510_018)
 else if (egrep (pattern:"SSPSOL510_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"SSPSOL510_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build < 18)
    vulnerable = TRUE;
 }
 # hp-ux security patch (fixed in SSPUX510_94)
 else if (egrep (pattern:"SSPUX510_[0-9]+", string:build))
 {
  build = ereg_replace (pattern:"SSPUX510_([0-9]+)$", string:build, replace:"\1");
  build = int (build);
  if (build < 94)
    vulnerable = TRUE;
 }
}

if (vulnerable)
{
  report = '\nVersion : '+version+'\nBuild : '+build+'\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN,"HP Data Protector", version, build);
