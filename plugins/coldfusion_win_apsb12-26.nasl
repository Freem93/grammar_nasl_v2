#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63690);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/23 21:23:02 $");

  script_cve_id("CVE-2012-5675");
  script_bugtraq_id(56900);
  script_osvdb_id(88355);

  script_name(english:"Adobe ColdFusion Unspecified Sandbox Bypass (APSB12-26) (credentialed check)");
  script_summary(english:"Checks for hotfix file.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web-based application running on the remote Windows host is affected
by a security bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of ColdFusion that is
affected by an unspecified sandbox permission bypass vulnerability. 
This vulnerability is present when ColdFusion is used in a
shared-hosting environment."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-26.html");
  # http://helpx.adobe.com/coldfusion/kb/coldfusion-security-hotfix-apsb12-26.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?625d67f5");
  script_set_attribute(attribute:"solution", value:"Apply the relevant hotfixes referenced in Adobe advisory APSB12-26.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_win_local_detect.nasl");
  script_require_keys("SMB/coldfusion/instance");
  script_require_ports(139, 445);

  exit(0);
}

include("coldfusion_win.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

versions = make_list('9.0.0', '9.0.1', '9.0.2', '10.0.0');
instances = get_coldfusion_instances(versions); # this exits if it fails
port   = kb_smb_transport();

# Check the hotfixes and cumulative hotfixes installed for each
# instance of ColdFusion.
info = NULL;
instance_info = make_list();

foreach name (keys(instances))
{
  info = NULL;
  ver = instances[name];

  if (ver == "9.0.0")
    info = check_jar_hotfix(name, "00008", 2, make_list("00001", "00002", "00003", "00004", "00005", "00006", "00007"));
  else if (ver == "9.0.1")
    info = check_jar_hotfix(name, "00007", 3, make_list("00001", "00002", "00003", "00004", "00005", "00006"));
  else if (ver == "9.0.2")
    info = check_jar_hotfix(name, "00002", 1, make_list("00001"));
  else if (ver == "10.0.0")
    info = check_jar_chf(name, 6);

  if (!isnull(info))
    instance_info = make_list(instance_info, info);
}

if (max_index(instance_info) == 0)
  exit(0, "No vulnerable instances of Adobe ColdFusion were detected.");

if (report_verbosity > 0)
{
  report =
    '\nNessus detected the following unpatched instances :' +
    '\n' + join(instance_info, sep:'\n') +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
