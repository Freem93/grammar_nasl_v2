#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90005);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/03 20:48:27 $");

  script_cve_id("CVE-2016-1731");
  script_bugtraq_id(84283);
  script_osvdb_id(135661);
  script_xref(name:"IAVB", value:"2016-B-0053");

  script_name(english:"Apple Software Update Insecure Transport");
  script_summary(english:"Checks the Apple Software Update version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that that uses an
insecure connection protocol for updating.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Software Update installed on the remote Mac OS X
host does not use the HTTPS protocol when transferring the updates
window contents. A man-in-the-middle attacker can exploit this
vulnerability, by modifying the data stream between the client and
server, to control the contents of the updates window.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT206091");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Software Update version 2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:software_update");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("apple_software_update_installed.nbin");
  script_require_keys("installed_sw/Apple Software Update");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "Apple Software Update";
get_kb_item_or_exit("installed_sw/" + app_name);

install = get_single_install(app_name: app_name, exit_if_unknown_ver: TRUE);

version = install['version'];
path = install['path'];
fix = "2.2";

if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port))
    port = 445;

  items = make_array("Path", path,
                     "Installed version", version,
                     "Fixed version", fix);

  order = make_list("Path", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);

}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
