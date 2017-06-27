#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72178);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2013-6810");
  script_bugtraq_id(64242);
  script_osvdb_id(100899, 101195, 101209, 101210, 101211);

  script_name(english:"HP B-series SAN Network Advisor < 12.1.1 Remote Code Execution (Linux)");
  script_summary(english:"Checks version of HP B-series SAN Network Advisor");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP B-series SAN Network Advisor on the remote Linux host
is a version prior to 12.1.1.  As such, it is affected by a remote code
execution vulnerability. 

It should be noted that while the associated references report on a
remote code execution vulnerability in EMC Connectrix Manager
Converged Network Edition, HP B-series SAN Network Advisor is the same
product under an HP name and is, therefore, also affected.  Moreover,
the issue is actually due to a third-party product from Brocade.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-278/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-279/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-280/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-281/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-282/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-283/");
  script_set_attribute(attribute:"see_also", value:"http://attrition.org/pipermail/vim/2014-January/002755.html");
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04045640
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46ff464a");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/530357/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP B-series SAN Network Advisor 12.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:b_series_san_network_advisor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_b-series_san_network_advisor_linux_installed.nbin");
  script_require_keys("Host/HP B-Series SAN Network Advisor/Installed");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

appname = "HP B-series SAN Network Advisor";

kb_base = "Host/HP B-Series SAN Network Advisor/";
ver = get_kb_item_or_exit(kb_base + "Version");
path = get_kb_item_or_exit(kb_base + "Path");

if (ver !~ "^[0-9.]+$") exit(1, "The version of "+appname+" ("+ver+") is not entirely numeric numeric.");

fix = "12.1.1";
min = "12.0.0";

if (ver_compare(ver:ver, fix:min, strict:FALSE) >= 0 && ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path);
