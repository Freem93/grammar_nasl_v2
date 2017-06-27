#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88718);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/04/15 13:47:37 $");

  script_cve_id(
    "CVE-2016-0951",
    "CVE-2016-0952",
    "CVE-2016-0953"
  );
  script_bugtraq_id(
    83114
  );
  script_osvdb_id(
    134281,
    134282,
    134283
  );

  script_name(english:"Adobe Bridge CC < 6.2 Multiple Memory Corruption Vulnerabilities (APSB16-03)");
  script_summary(english:"Checks the Bridge version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by
multiple memory corruption vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Bridge installed on the remote Windows host is
prior to 6.2. It is, therefore, affected by multiple unspecified
memory corruption issues due to improper validation of user-supplied
input. An unauthenticated, remote attacker can exploit these issues to
execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb16-03.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Bridge CC version 6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge_cc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("adobe_bridge_installed.nasl");
  script_require_keys("installed_sw/Adobe Bridge");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("installed_sw/Adobe Bridge");

app_name = "Adobe Bridge";

install = get_single_install(app_name: app_name, exit_if_unknown_ver: TRUE);

product_name = install['Product'];
if ("CC" >!< product_name)
  exit(0, "Only Adobe Bridge CC is affected.");

ver = install['version'];
path = install['path'];

# version < 6.1.1 Vuln
fix = '6.2';

if (ver_compare(ver: ver, fix: fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  if (report_verbosity > 0)
  {
    report = '\n  Product           : ' + product_name +
             '\n  Path              : ' + path +
             '\n  Installed version : ' + ver +
             '\n  Fixed version     : ' + fix +
             '\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver, path);
