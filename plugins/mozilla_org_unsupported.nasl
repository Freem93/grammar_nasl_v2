#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40362);
  script_version("$Revision: 1.88 $");
  script_cvs_date("$Date: 2017/05/11 21:50:17 $");

  script_name(english:"Mozilla Foundation Unsupported Application Detection");
  script_summary(english:"Checks if any Mozilla application versions are unsupported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains one or more unsupported applications from the
Mozilla Foundation.");
  script_set_attribute(attribute:"description", value:
"According to its version, there is at least one unsupported Mozilla
application (Firefox, Thunderbird, and/or SeaMonkey) installed on the
remote host. This version of the software is no longer actively
maintained.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/firefox/organizations/faq/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/known-vulnerabilities/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/firefox/new/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/thunderbird/");
  script_set_attribute(attribute:"see_also", value:"https://www.seamonkey-project.org/releases/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version that is currently supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_ports("installed_sw/Mozilla Firefox", "installed_sw/Mozilla Firefox ESR", "installed_sw/Mozilla Thunderbird", "installed_sw/Mozilla Thunderbird ESR", "installed_sw/SeaMonkey");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

all_latest_version_data = make_array(
  'Mozilla Firefox'        , "53.0.2",
  'Mozilla Firefox ESR'    , "52.1.1",
  'Mozilla Thunderbird'    , "52.1",
  'Mozilla Thunderbird ESR', "Defunct.",
  'SeaMonkey'              , "2.40"
);

all_unsupported_data = make_array(

  ##########
  # Mozilla Firefox (NOT ESR)
  ##########
  'Mozilla Firefox', make_array(
    '^5[0-1]\\.', 'https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox-51/',
    '^4[0-9]\\.', 'https://wiki.mozilla.org/Releases#Previous_Releases',
    '^3[0-9]\\.', 'https://wiki.mozilla.org/Releases#Previous_Releases',
    '^2[0-9]\\.', 'https://wiki.mozilla.org/Releases#Previous_Releases',
    '^1[0-9]\\.', 'https://wiki.mozilla.org/Releases#Previous_Releases',
    '^[4-9]\\.', 'http://mozilla.github.com/process-releases/draft/development_overview/',
    '^3\\.6\\.', 'https://blog.mozilla.org/futurereleases/2012/03/23/upcoming-firefox-support-changes/',
    '^3\\.5\\.', 'https://developer.mozilla.org/devnews/index.php/2011/04/28/firefox-4-0-1-3-6-17-and-3-5-19-security-updates-now-available/',
    '^3\\.0\\.', 'https://wiki.mozilla.org/Releases/Firefox_3.0.19',
    '^2\\.0\\.', 'http://www.mozilla.org/security/known-vulnerabilities/firefox20.html',
    '^1\\.5\\.', 'http://www.mozilla.org/security/known-vulnerabilities/firefox15.html',
    '^1\\.0\\.', 'http://www.mozilla.org/security/known-vulnerabilities/firefox10.html',
    '^0\\.', NULL
  ),

  ##########
  # Mozilla Firefox ESR
  ##########
  'Mozilla Firefox ESR', make_array(
    '^38\\.[0-8]\\.', 'https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox-esr-38/',
    '^3[0-7]\\.', 'https://wiki.mozilla.org/Releases#Previous_Releases',
    '^2[0-9]\\.', 'https://wiki.mozilla.org/Releases#Previous_Releases',
    '^1[0-9]\\.', 'https://wiki.mozilla.org/Releases#Previous_Releases'
  ),

  ##########
  # Mozilla Thunderbird (NOT ESR)
  ##########
  'Mozilla Thunderbird', make_array(
    '^3[0-7]\\.', 'https://wiki.mozilla.org/Releases#Previous_Releases',
    '^2[0-9]\\.', 'https://wiki.mozilla.org/Releases#Previous_Releases',
    '^1[0-9]\\.', 'https://wiki.mozilla.org/Releases#Previous_Releases',
    '^[4-9]\\.', 'http://people.mozilla.org/~mbanner2/tbdevspecifics/',
    '^3\\.1\\.', 'https://support.mozillamessaging.com/en-US/kb/upgrading-thunderbird-31',
    '^3\\.0\\.', 'https://wiki.mozilla.org/Releases/Thunderbird_3.0.11',
    '^2\\.0\\.', 'https://developer.mozilla.org/devnews/index.php/2010/04/09/thunderbird-2-0-0-24-security-update-available-for-download/',
    '^1\\.5\\.', 'http://www.mozilla.org/security/known-vulnerabilities/thunderbird15.html',
    '^1\\.0\\.', 'http://www.mozilla.org/security/known-vulnerabilities/thunderbird10.html',
    '^0\\.', NULL
  ),

  ##########
  # Mozilla Thunderbird ESR
  # Defunct - *all* versions of ESR are no longer supported.
  ##########
  'Mozilla Thunderbird ESR', make_array(
    '^\\d', 'https://wiki.mozilla.org/Releases#Previous_Releases'
  ),

  ##########
  # SeaMmonkey
  ##########
  'SeaMonkey', make_array(
    '^1\\.1\\.', 'http://www.seamonkey-project.org/news#2010-03-16',
    '^1\\.0\\.', 'http://www.mozilla.org/security/known-vulnerabilities/seamonkey10.html',
    '^0\\.', NULL
  )
);

products = make_list(
  "Mozilla Firefox",
  "Mozilla Firefox ESR",
  "Mozilla Thunderbird",
  "Mozilla Thunderbird ESR",
  "SeaMonkey"
);

# Branch on product
product = branch(products);

# Branch on install
install = get_single_install(app_name:product);
version = install['version'];
path    = install['path'];
unsupported_data    = all_unsupported_data[product];
latest_version = all_latest_version_data[product];

# Check version for unsupported status
foreach regex (keys(unsupported_data))
{
  if (version !~ regex) continue;

  eol_url = unsupported_data[regex];

  match = eregmatch(pattern:"^([0-9]+)\.", string:version);
  if (isnull(match)) version_highlevel = version;
  else version_highlevel = match[1];

  cpe_base = tolower(str_replace(string:product, find:"Mozilla ", replace:""));
  cpe_base = str_replace(string:cpe_base, find:" ", replace:"_");

  register_unsupported_product(
    product_name : product,
    cpe_base     : "mozilla:" + cpe_base,
    version      : version_highlevel
  );
  break;
}

if (eol_url)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Product           : ' + product +
      '\n  Path              : ' + path    +
      '\n  Installed version : ' + version +
      '\n  Latest version    : ' + latest_version +
      '\n  EOL URL           : ' + eol_url +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port:port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, product, version, path);
