#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56710);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/03/03 22:36:31 $");

  script_name(english:"Wireshark / Ethereal Unsupported Version Detection");
  script_summary(english:"Checks the version of Wireshark / Ethereal.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Wireshark /
Ethereal.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Wireshark / Ethereal on
the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://wiki.wireshark.org/Development/LifeCycle");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Wireshark that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl", "macosx_wireshark_installed.nbin");
  script_require_ports("installed_sw/Wireshark", "installed_sw/Ethereal");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

apps = make_list();

if (get_install_count(app_name:"Wireshark") > 0) apps = make_list(apps, "Wireshark");
if (get_install_count(app_name:"Ethereal")  > 0) apps = make_list(apps, "Ethereal");

if (empty(apps)) audit(AUDIT_NOT_INST, "Wireshark/Ethereal");

# Odd minor versions are dev branches
eos_dates = make_array(
  "^1\.(11|12)($|\.)",  'July 31,2016',
  "^1\.(9|10)($|\.)",  'June 5, 2015',
  "^1\.[78]($|\.)",    'June 21, 2014',
  "^1\.[56]($|\.)",    'June 7, 2013',
  "^1\.[34]($|\.)",    'August 30, 2012',
  "^1\.[12]($|\.)",    'June 30, 2011',
  "^(0\.|1\.0($|\.))", 'September 30, 2010'
);
withdrawl_announcements = make_array(
  "^1\.(11|12)($|\.)",  'https://wiki.wireshark.org/Development/LifeCycle',
  "^1\.(9|10)($|\.)",  'https://wiki.wireshark.org/Development/LifeCycle',
  "^1\.[78]($|\.)",    'http://www.wireshark.org/lists/wireshark-announce/201406/msg00001.html',
  "^1\.[56]($|\.)",    'http://www.wireshark.org/lists/wireshark-announce/201306/msg00002.html',
  "^1\.[34]($|\.)",    'http://www.wireshark.org/lists/wireshark-announce/201208/msg00003.html',
  "^1\.[12]($|\.)",    'http://www.wireshark.org/lists/wireshark-announce/201108/msg00000.html',
  "^(0\.|1\.0($|\.))", 'http://www.wireshark.org/news/20100731.html'
);

# Ethereal info
ethereal_eos_date = 'Jun 7, 2006';
ethereal_withdrawl_announcement = 'http://www.wireshark.org/news/20060607.html';

supported_versions = '2.x';

foreach app (apps)
{
  install = get_single_install(app_name:app, exit_if_unknown_ver:FALSE);
  version = install['version'];
  if (version == UNKNOWN_VER) continue;
  path    = install['path'];
  report  = NULL;

  # Determine support status
  foreach v (keys(eos_dates))
  {
    if (version =~ v)
    {
      register_unsupported_product(product_name:app,
                                   version:version,
                                   cpe_base:tolower(app) + ":" + tolower(app));
      report +=
        '\n  Path                : ' + path +
        '\n  Installed version   : ' + version;

      if (app == 'Wireshark')
      {
        if (eos_dates[v])
          report += '\n  End of support date : ' + eos_dates[v];
        if (withdrawl_announcements[v])
          report += '\n  Announcement        : ' + withdrawl_announcements[v];
        report +=   '\n  Supported versions  : ' + supported_versions + '\n';
      }
      else
      {
        report += '\n  End of support date : ' + ethereal_eos_date;
        report += '\n  Announcement        : ' + ethereal_withdrawl_announcement;
        report += '\n  Supported versions  : Ethereal is no longer supported.\n';
      }

      break;
    }
  }
  
  if (isnull(report)) audit(AUDIT_SUPPORTED, app, version, path);

  # Report
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);
}
