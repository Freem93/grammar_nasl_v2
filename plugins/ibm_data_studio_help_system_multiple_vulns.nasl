#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65576);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/16 14:02:51 $");

  script_cve_id("CVE-2012-2159", "CVE-2012-2161", "CVE-2013-0467");
  script_bugtraq_id(53884, 58000);
  script_osvdb_id(82711, 82754, 90318);

  script_name(english:"IBM Data Studio 3.1 / 3.1.1 Help System Multiple Vulnerabilities");
  script_summary(english:"Checks version of IBM Data Studio");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application installed that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of IBM Data Studio installed that is
affected by multiple vulnerabilities :

  - An unspecified open-redirect vulnerability exists in the
    Eclipse help system components. (CVE-2012-2159)

  - An unspecified cross-site scripting vulnerability exists
    in the Eclipse help system components. (CVE-2012-2161)

  - An unspecified vulnerability exists that could allow
    disclosure of source code on the help system server.
    (CVE-2013-0467)"
  );
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21625573");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24033663");
  script_set_attribute(attribute:"solution", value:"Upgrade to IBM Data Studio 3.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:data_studio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_data_studio_installed.nasl");
  script_require_keys("SMB/ibm_data_studio/Version");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("global_settings.inc");
include("misc_func.inc");

app = 'IBM Data Studio';
kb_base = "SMB/ibm_data_studio/";
port = kb_smb_transport();

version = get_kb_item_or_exit(kb_base + "Version");
path = get_kb_item_or_exit(kb_base + "Path");

if (version == "unknown") exit(0, "Version information not available.");

fix = "3.2";
if (version == "3.1" || version == "3.1.1")
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
