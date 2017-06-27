#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65723);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/16 14:02:51 $");

  script_cve_id("CVE-2013-2493");
  script_bugtraq_id(58562);
  script_osvdb_id(91114);

  script_name(english:"Google Chrome Frame < 26.0.1410.28 Denial of Service");
  script_summary(english:"Checks version number of Google Chrome Frame");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a web browser plugin that is affected by a
denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Google Chrome Frame installed on the remote host is
earlier than 26.0.1410.28.  Such versions are affected by a
vulnerability that could allow an attacker to trigger a browser crash by
tricking a victim into opening a specially crafted HTML document."
  );
  script_set_attribute(attribute:"see_also", value:"https://code.google.com/p/chromium/issues/detail?id=178415");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome Frame 26.0.1410.28 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome_frame");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_frame_installed.nasl");
  script_require_keys("SMB/Google_Chrome_Frame/Installed");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");

# Check each installation.
installs = get_kb_list_or_exit("SMB/Google_Chrome_Frame/*");

info = "";
vulns = make_array();

fix_version = "26.0.1410.28";

foreach install(sort(keys(installs)))
{
  if ("/Installed" >< install) continue;

  version = install - "SMB/Google_Chrome_Frame/";

  if (ver_compare(ver:version, fix:fix_version, strict:FALSE) == -1)
    vulns[version] =  installs[install];
}

# Report if vulnerable installs were found.
if (max_index(keys(vulns)))
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    info = "";
    n = 0;
    foreach version (sort(keys(vulns)))
    {
      path = vulns[version];
      if(!isnull(path))
      {
        info +=
          '\n  Path              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : ' + fix_version +
          '\n';
        n++;
      }
    }
    info += '\n';

    if (n > 1) s = "s of Google Chrome Frame are";
    else s = " of Google Chrome Frame is";

    report =
      '\n' +
      "The following vulnerable instance" + s + " installed on" + '\n' +
      "the remote host :" + '\n' +
      info;

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else
{
  if (thorough_tests)
    exit(0,"No vulnerable versions of Google Chrome Frame were found.");
  else exit(1, "Some installs may have been missed because the 'Perform thorough tests' setting was not enabled.");
}
