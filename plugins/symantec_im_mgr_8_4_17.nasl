#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(52052);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/17 15:15:44 $");

  script_cve_id("CVE-2010-3719");
  script_bugtraq_id(45946);
  script_osvdb_id(70755);
 
  script_name(english:"Symantec IM Manager IMAdminSchedTask.asp Eval Code Injection Remote Code Execution (SYM11-004)");
  script_summary(english:"Checks build version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote Windows host can be abused to execute
arbitrary code."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Symantec IM Manager installed on the remote Windows
host is earlier than 8.4.17.  The 'ScheduleTask' method exposed by the
'IMAdminSchedTask.asp' page fails to properly sanitize user input to a
POST variable before using it in an 'eval()' call. 

If a logged in console user can be tricked into visiting a malicious
link, this issue can be exploited to inject and execute arbitrary ASP
code and compromise the affected application."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-11-037"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/fulldisclosure/2011/Jan/584"
  );
  # http://www.symantec.com/business/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2011&suid=20110131_00
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?9ebaace1"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.symantec.com/docs/TECH88765"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Symantec IM Manager 8.4.17 (build 8.4.1397) or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:im_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

fixed_build = "8.4.1397";

if (ver_compare(ver:build, fix:fixed_build, strict:FALSE) == -1)
{
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
