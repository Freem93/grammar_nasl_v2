#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90544);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/04/15 18:54:40 $");

  script_name(english:"Apple QuickTime Unsupported on Windows");
  script_summary(english:"Checks for QuickTime on Windows.");

  script_xref(name:"ZDI", value:"ZDI-16-241");
  script_xref(name:"ZDI", value:"ZDI-16-242");

  script_set_attribute(attribute:"synopsis", value:
"Apple QuickTime is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Apple no longer supports any version of QuickTime on Windows.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.

Note that the last version of QuickTime released for Windows had known
vulnerabilities related to processing atom indexes. A remote attacker
can exploit these, by convincing a user to view a malicious website
or open a crafted file, to cause heap corruption within QuickTime,
resulting in the execution of arbitrary code in the context of the
user or process running QuickTime.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/HT205771");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-242/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-16-241/");
  script_set_attribute(attribute:"see_also", value:"https://www.us-cert.gov/ncas/alerts/TA16-105A");
  script_set_attribute(attribute:"solution", value:
"Uninstall Apple QuickTime.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("quicktime_installed.nasl");
  script_require_keys("installed_sw/QuickTime for Windows");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'QuickTime for Windows';
get_install_count(app_name:app, exit_if_zero:TRUE);
install = get_single_install(app_name:app);
version = install['version'];
path = install['path'];

register_unsupported_product(
  product_name : app,
  version      : version,
  cpe_class    : CPE_CLASS_APPLICATION,
  cpe_base     : "apple:quicktime:windows"
);

order = make_list(
  'Path',
  'Installed version',
  'End of support date',
  'Supported versions'
);

report = make_array(
  order[0], path,
  order[1], version,
  order[2], "2016/04/01",
  order[3], "None, remove QuickTime"
);

report = report_items_str(
  report_items   : report,
  ordered_fields : order
);

port = get_kb_item("SMB/transport");
if (!port) port = 445;
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
