#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58388);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2012-0770");
  script_bugtraq_id(52436);
  script_osvdb_id(80008);
  script_xref(name:"CERT", value:"903934");

  script_name(english:"Adobe ColdFusion Hash Collision DoS (APSB12-06) (credentialed check)");
  script_summary(english:"Checks for hotfix file");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web-based application running on the remote Windows host is affected
by a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of ColdFusion that is
affected by a hash collision denial of service. A flaw exists in
the way ColdFusion generates hash tables for user-supplied values.
By sending a small number of specially crafted requests to a web
server that uses ColdFusion, an attacker can take advantage of this
flaw to cause a denial of service condition."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nruns.com/_downloads/advisory28122011.pdf");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-06.html");
  script_set_attribute(attribute:"see_also", value:"https://www.adobe.com/support/security/bulletins/apsb12-06.html");
  script_set_attribute(
    attribute:"solution",
    value:"Apply the relevant hotfixes referenced in Adobe advisory APSB12-06."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_win_local_detect.nasl");
  script_require_keys("SMB/coldfusion/instance");
  script_require_ports(139, 445);

  exit(0);
}

include("coldfusion_win.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

versions = make_list('8.0.0', '8.0.1', '9.0.0', '9.0.1');
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

  if (ver == "8.0.0")
    info = check_jar_hotfix(name, "00005", 4, make_list("00001", "00002", "00003", "00004", "1875", "1878", "70523", "71471", "73122", "77218"));
  else if (ver == "8.0.1")
    info = check_jar_hotfix(name, "00005", 5, make_list("00001", "00002", "00003", "00004", "1875", "1878", "71471", "73122", "77218"));
  else if (ver == "9.0.0")
    info = check_jar_hotfix(name, "00005", 2, make_list("00001", "00002", "00003", "00004"));
  else if (ver == "9.0.1")
    info = check_jar_hotfix(name, "00004", 3, make_list("00001","00002","00003"));

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
