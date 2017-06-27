#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72962);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/01/28 15:42:43 $");

  script_cve_id(
    "CVE-2012-2088",
    "CVE-2013-2909",
    "CVE-2013-2926",
    "CVE-2013-2928",
    "CVE-2013-5196",
    "CVE-2013-5197",
    "CVE-2013-5198",
    "CVE-2013-5199",
    "CVE-2013-5225",
    "CVE-2013-5228",
    "CVE-2013-6625",
    "CVE-2013-6629",
    "CVE-2013-6635",
    "CVE-2014-1267",
    "CVE-2014-1269",
    "CVE-2014-1270",
    "CVE-2014-1271",
    "CVE-2014-1272",
    "CVE-2014-1273",
    "CVE-2014-1275",
    "CVE-2014-1278",
    "CVE-2014-1279",
    "CVE-2014-1280",
    "CVE-2014-1282",
    "CVE-2014-1287",
    "CVE-2014-1289",
    "CVE-2014-1290",
    "CVE-2014-1291",
    "CVE-2014-1292",
    "CVE-2014-1293",
    "CVE-2014-1294"
  );
  script_bugtraq_id(
    54270,
    63024,
    63028,
    63672,
    63676,
    64354,
    64356,
    64358,
    64359,
    64360,
    64361,
    64362,
    65779,
    65780,
    65781,
    66088,
    66089,
    66090
  );
  script_osvdb_id(
    83628,
    97970,
    98593,
    98594,
    98595,
    99711,
    99715,
    100584,
    101091,
    101092,
    101093,
    101094,
    101095,
    101096,
    103710,
    103711,
    104260,
    104261,
    104262,
    104263,
    104265,
    104268,
    104269,
    104273,
    104274,
    104275,
    104289,
    104290,
    104291,
    104292,
    104293,
    104294
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-03-10-2");

  script_name(english:"Apple TV < 6.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version in banner");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote Apple TV 2nd generation or later
device is prior to 6.1. It is, therefore, reportedly affected by
multiple vulnerabilities, the most serious issues of which could
result in arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6163");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/531397/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple TV 6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("appletv_detect.nasl");
  script_require_keys("www/appletv");
  script_require_ports(3689);
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = 3689;
banner = get_http_banner(port:port, broken:TRUE, exit_on_fail:TRUE);
if (
  "DAAP-Server: iTunes/" >!< banner &&
  "RIPT-Server: iTunesLib/" >!< banner
) audit(AUDIT_WRONG_WEB_SERVER, port, 'iTunes');

pat = "^DAAP-Server: iTunes/([0-9][0-9.]+)([a-z])([0-9]+) \((Mac )?OS X\)";
matches = egrep(pattern:pat, string:banner);

if (
  "DAAP-Server: iTunes/" >< banner &&
  !matches
) exit(0, "The web server listening on port "+port+" does not appear to be from iTunes on an Apple TV.");


fixed_major = "11.1";
fixed_char = "b";
fixed_minor = "37";
fixed_airtunes_version = "200.54";

report = "";

# Check first for 3rd gen and recent 2nd gen models.
if (matches)
{
  foreach line (split(matches, keep:FALSE))
  {
    match = eregmatch(pattern:pat, string:line);
    if (!isnull(match))
    {
      major = match[1];
      char = match[2];
      minor = int(match[3]);

      if (
        ver_compare(ver:major, fix:fixed_major, strict:FALSE) < 0 ||
        (
          ver_compare(ver:major, fix:fixed_major, strict:FALSE) == 0 &&
          (
            ord(char) < ord(fixed_char) ||
            (
              ord(char) == ord(fixed_char) &&
              minor < fixed_minor
            )
          )
        )
      )
      {
        report = '\n  Source                   : ' + line +
                 '\n  Installed iTunes version : ' + major + char + minor +
                 '\n  Fixed iTunes version     : ' + fixed_major + fixed_char + fixed_minor +
                 '\n';
      }
      else if (major == fixed_major && char == fixed_char && minor == fixed_minor)
      {
        airtunes_port = 5000;
        # nb: 'http_server_header()' exits if it can't get the HTTP banner.
        server_header = http_server_header(port:airtunes_port);
        if (isnull(server_header)) audit(AUDIT_WEB_NO_SERVER_HEADER, airtunes_port);
        if ("AirTunes" >!< server_header)  audit(AUDIT_WRONG_WEB_SERVER, airtunes_port, "AirTunes");

        match = eregmatch(string:server_header, pattern:"^AirTunes\/([0-9][0-9.]+)");
        if (!match) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, "AirTunes", airtunes_port);
        airtunes_version = match[1];

        if (ver_compare(ver:airtunes_version, fix:fixed_airtunes_version, strict:FALSE) < 0)
        {
          report = '\n  Source                     : ' + server_header +
                   '\n  Installed AirTunes version : ' + airtunes_version +
                   '\n  Fixed AirTunes version     : ' + fixed_airtunes_version +
                   '\n';
        }
        else exit(0, "The web server listening on port "+airtunes_port+" reports itself as 'AirTunes/"+airtunes_version+"' and, therefore, is not affected.");
      }
    }
  }
}
else
{
  pat2 = "^RIPT-Server: iTunesLib/([0-9]+)\.";
  matches = egrep(pattern:pat2, string:banner);
  if (matches)
  {
    foreach line (split(matches, keep:FALSE))
    {
      match = eregmatch(pattern:pat2, string:line);
      if (!isnull(match))
      {
        major = int(match[1]);
        if (major < 4) exit(0, "The web server listening on port "+port+" is from iTunes on a 1st generation Apple TV, which is no longer supported.");
        else if (major >= 4 && major <= 9)
        {
          report = '\n  Source : ' + line +
                   '\n';
        }
        break;
      }
    }
  }
}


if (report)
{
  if (report_verbosity > 0) security_hole(port:0, extra:report);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
