#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70257);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/19 17:45:32 $");

  script_cve_id(
    "CVE-2011-2391",
    "CVE-2011-3102",
    "CVE-2012-0841",
    "CVE-2012-2807",
    "CVE-2012-2825",
    "CVE-2012-2870",
    "CVE-2012-2871",
    "CVE-2012-5134",
    "CVE-2013-0879",
    "CVE-2013-0991",
    "CVE-2013-0992",
    "CVE-2013-0993",
    "CVE-2013-0994",
    "CVE-2013-0995",
    "CVE-2013-0996",
    "CVE-2013-0997",
    "CVE-2013-0998",
    "CVE-2013-0999",
    "CVE-2013-1000",
    "CVE-2013-1001",
    "CVE-2013-1002",
    "CVE-2013-1003",
    "CVE-2013-1004",
    "CVE-2013-1005",
    "CVE-2013-1006",
    "CVE-2013-1007",
    "CVE-2013-1008",
    "CVE-2013-1010",
    "CVE-2013-1011",
    "CVE-2013-1019",
    "CVE-2013-1025",
    "CVE-2013-1026",
    "CVE-2013-1037",
    "CVE-2013-1038",
    "CVE-2013-1039",
    "CVE-2013-1040",
    "CVE-2013-1041",
    "CVE-2013-1042",
    "CVE-2013-1043",
    "CVE-2013-1044",
    "CVE-2013-1045",
    "CVE-2013-1046",
    "CVE-2013-1047",
    "CVE-2013-2842",
    "CVE-2013-3950",
    "CVE-2013-3953",
    "CVE-2013-3954",
    "CVE-2013-5125",
    "CVE-2013-5126",
    "CVE-2013-5127",
    "CVE-2013-5128",
    "CVE-2013-5138",
    "CVE-2013-5139",
    "CVE-2013-5140",
    "CVE-2013-5142",
    "CVE-2013-5145"
  );
  script_bugtraq_id(
    52107,
    53540,
    54203,
    54718,
    55331,
    56684,
    59326,
    59944,
    59953,
    59954,
    59955,
    59956,
    59957,
    59958,
    59959,
    59960,
    59963,
    59964,
    59965,
    59967,
    59970,
    59971,
    59972,
    59973,
    59974,
    59976,
    59977,
    60067,
    60102,
    60437,
    60441,
    60444,
    62368,
    62369,
    62520,
    62522,
    62524,
    62529,
    62531,
    62536,
    62551,
    62553,
    62554,
    62556,
    62557,
    62558,
    62559,
    62560,
    62563,
    62565,
    62567,
    62568,
    62569,
    62570,
    62571
  );
  script_osvdb_id(
    79437,
    81964,
    83255,
    83266,
    85035,
    85036,
    87882,
    90521,
    91608,
    92818,
    93470,
    93471,
    93472,
    93473,
    93474,
    93475,
    93476,
    93477,
    93478,
    93479,
    93480,
    93481,
    93482,
    93483,
    93484,
    93485,
    93486,
    93487,
    93488,
    93489,
    93622,
    93959,
    93962,
    93963,
    97281,
    97282,
    97434,
    97435,
    97436,
    97438,
    97439,
    97440,
    97488,
    97489,
    97490,
    97491,
    97492,
    97493,
    97494,
    97495,
    97496,
    97497,
    97498,
    97499,
    97500,
    97501,
    97502
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-09-20-1");

  script_name(english:"Apple TV < 6.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version in banner");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote Apple TV 2nd generation or later
device is prior to 6.0.  It is, therefore, reportedly affected by
multiple vulnerabilities, the most serious issues of which could
result in arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5935");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Sep/msg00008.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/528762/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple TV 6.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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
  isnull(matches)
) exit(0, "The web server listening on port "+port+" does not appear to be from iTunes on an Apple TV.");


fixed_major = "11.1";
fixed_char = "b";
fixed_minor = "37";

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
      break;
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
