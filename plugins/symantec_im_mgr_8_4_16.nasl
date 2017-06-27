#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50432);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/17 15:15:44 $");

  script_cve_id("CVE-2010-0112");
  script_bugtraq_id(44299);
  script_osvdb_id(68898, 68899, 68900, 68901, 68902, 68903);
 
  script_name(english:"Symantec IM Manager < 8.4.16 Multiple SQL Injections (SYM10-010)");
  script_summary(english:"Checks build version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote Windows host may be affected by
multiple SQL injection vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Symantec IM Manager installed on the remote Windows
host is earlier than 8.4.16.  Such versions are reportedly affected by
multiple SQL injection vulnerabilities in its administration console.

An unauthenticated, remote attacker may be able to exploit these issues
to compromise the application's database."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-220/"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-221/"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-222/"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-223"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-224/"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-225/"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-10-226/"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/fulldisclosure/2010/Oct/429"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/fulldisclosure/2010/Oct/430"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/fulldisclosure/2010/Oct/426"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/fulldisclosure/2010/Oct/424"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/fulldisclosure/2010/Oct/425"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/fulldisclosure/2010/Oct/427"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/fulldisclosure/2010/Oct/428"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?bf68d8df"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Symantec IM Manager 8.4.16 (build 8.4.1393) or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:im_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_im_mgr_installed.nasl");
  script_require_keys("SMB/Symantec/im_mgr/Build");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


build = get_kb_item_or_exit('SMB/Symantec/im_mgr/Build');
build_pat = "^([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+$";
if (eregmatch(pattern:build_pat, string:build))
  build = ereg_replace(pattern:build_pat, replace:"\1", string:build);

fixed_build = "8.4.1393";

if (ver_compare(ver:build, fix:fixed_build, strict:FALSE) == -1)
{
  set_kb_item(name:'www/0/SQLInjection', value:TRUE);

  path = get_kb_item('SMB/Symantec/im_mgr/Path');
  if (isnull(path)) path = 'n/a';

  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    report = '\n  Path                    : '+path+
             '\n  Installed build version : '+build+
             '\n  Fixed build version     : '+fixed_build+'\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "Symantec IM Manager build version "+build+" is installed and not affected.");
