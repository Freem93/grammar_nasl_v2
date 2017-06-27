#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(55749);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2011/10/24 19:04:29 $");

  script_cve_id("CVE-2011-1544", "CVE-2011-1545");
  script_bugtraq_id(47524);
  script_osvdb_id(71903, 71904);
  script_xref(name:"Secunia", value:"44216");

  script_name(english:"HP Insight Control Performance Management < 6.3 Multiple Vulnerabilities");
  script_summary(english:"Checks version of HP Insight Control Performance Management");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a management application that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the HP Insight Control Performance
Management install on the remote Windows host is affected by multiple
vulnerabilities :

  - An unspecified vulnerability could allow remote 
    authenticated users to gain elevated privileges.
    (CVE-2011-1544)

  - A cross-site request forgery vulnerability exists that
    can be exploited via unknown vectors. (CVE-2011-1545)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a09bb2f");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP Insight Control Performance Management 6.3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/01");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:insight_control_performance_management");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

  script_dependencies("hp_insight_performance_mgmt_installed.nasl");
  script_require_keys("SMB/HP Insight Control Performance Management/Version");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('smb_func.inc');

path = get_kb_item_or_exit('SMB/HP Insight Control Performance Management/Path');
version = get_kb_item_or_exit('SMB/HP Insight Control Performance Management/Version');

fixed_version = '6.3.0';
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.3.0 \n';
    security_warning(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_warning(get_kb_item('SMB/transport'));
  exit(0);
}
else exit(0, 'HP Insight Control Performance Management version '+version+' is installed and thus is not affected.');
