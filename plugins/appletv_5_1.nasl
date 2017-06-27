#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62357);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/19 17:45:32 $");

  script_cve_id(
    "CVE-2011-1167",
    "CVE-2011-1944",
    "CVE-2011-2821",
    "CVE-2011-2834",
    "CVE-2011-3026",
    "CVE-2011-3048",
    "CVE-2011-3328",
    "CVE-2011-3919",
    "CVE-2011-4599",
    "CVE-2012-0682",
    "CVE-2012-0683",
    "CVE-2012-1173",
    "CVE-2012-3589",
    "CVE-2012-3590",
    "CVE-2012-3591",
    "CVE-2012-3592",
    "CVE-2012-3678",
    "CVE-2012-3679",
    "CVE-2012-3722",
    "CVE-2012-3725",
    "CVE-2012-3726"
  );
  script_bugtraq_id(
    46951,
    48056,
    49279,
    49658,
    49744,
    51006,
    51300,
    52049,
    52830,
    52891,
    54680,
    56264,
    56268,
    56273
  );
  script_osvdb_id(
    71256,
    73248,
    74695,
    75560,
    75676,
    77698,
    78148,
    79294,
    80822,
    81025,
    84140,
    84141,
    84142,
    84143,
    84193,
    84194,
    84211,
    84212,
    85628,
    85635,
    85649
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2012-09-24-1");

  script_name(english:"Apple TV < 5.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version in banner");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote Apple TV 2nd generation or later
device has a version of iOS that is prior to 5.1. It is, therefore,
reportedly affected by several vulnerabilities :

  - An uninitialized memory access issue in the handling of
    Sorenson encoded movie files could lead to arbitrary
    code execution. (CVE-2012-3722)

  - Following the DNAv4 protocol, the device may broadcast
    MAC addresses of previously accessed networks when
    connecting to a Wi-Fi network. (CVE-2012-3725)

  - A buffer overflow in libtiff's handling of ThunderScan
    encoded TIFF images could lead to arbitrary code
    execution. (CVE-2011-1167)

  - Multiple memory corruption issues in libpng's handling
    of PNG images could lead to arbitrary code execution.
    (CVE-2011-3026 / CVE-2011-3048 / CVE-2011-3328)

  - A double free issue in ImageIO's handling of JPEG
    images could lead to arbitrary code execution.
    (CVE-2012-3726)

  - An integer overflow issue in libTIFF's handling of TIFF
    images could lead to arbitrary code execution.
    (CVE-2012-1173)

  - A stack-based buffer overflow in the handling of ICU
    locale IDs could lead to arbitrary code execution.
    (CVE-2011-4599)

  - Multiple vulnerabilities in libxml could have a variety
    of impacts, including arbitrary code execution.
    (CVE-2011-1944 / CVE-2011-2821 / CVE-2011-2834 /
    CVE-2011-3919)

  - Multiple memory corruption issues in JavaScriptCore
    could lead to arbitrary code execution.
    (CVE-2012-0682 / CVE-2012-0683 / CVE-2012-3589 /
    CVE-2012-3590 / CVE-2012-3591 / CVE-2012-3592 /
    CVE-2012-3678 / CVE-2012-3679)");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5504");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Sep/msg00006.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524229/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade the Apple TV to iOS 5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

pat = "^DAAP-Server: iTunes/([0-9][0-9.]+)[a-z]([0-9]+) \((Mac )?OS X\)";
if (
  "DAAP-Server: iTunes/" >< banner &&
  !egrep(pattern:pat, string:banner)
) exit(0, "The web server listening on port "+port+" does not appear to be from iTunes on an Apple TV.");


fixed_major = "11.0";
fixed_minor = "46";

report = "";

# Check first for 3rd gen and recent 2nd gen models.
matches = egrep(pattern:pat, string:banner);
if (matches)
{
  foreach line (split(matches, keep:FALSE))
  {
    match = eregmatch(pattern:pat, string:line);
    if (!isnull(match))
    {
      major = match[1];
      minor = match[2];

      if (
        ver_compare(ver:major, fix:fixed_major, strict:FALSE) < 0 ||
        (
          ver_compare(ver:major, fix:fixed_major, strict:FALSE) == 0 &&
          int(minor) < int(fixed_minor)
        )
      )
      {
        report = '\n  Source                   : ' + line +
                 '\n  Installed iTunes version : ' + major + 'd' + minor +
                 '\n  Fixed iTunes version     : ' + fixed_major + 'd' + fixed_minor +
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
