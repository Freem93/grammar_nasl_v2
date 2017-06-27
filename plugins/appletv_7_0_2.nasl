#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79360);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/01/28 15:42:43 $");

  script_cve_id(
    "CVE-2014-4452",
    "CVE-2014-4455",
    "CVE-2014-4461",
    "CVE-2014-4462"
  );
  script_bugtraq_id(71136, 71137, 71140, 71142);
  script_osvdb_id(114726, 114727, 114733, 114734);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-11-17-3");

  script_name(english:"Apple TV < 7.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version in the banner.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote Apple TV device is a version prior
to 7.0.2. It is, therefore, affected by the following
vulnerabilities :

  - Multiple memory corruption issues exist related to the
    included version of WebKit that allow application
    crashes or arbitrary code execution. (CVE-2014-4452,
    CVE-2014-4462)

  - A state management issue exists due to improperly
    handling overlapping segments in Mach-O executable
    files. A local user can exploit this issue to execute
    unsigned code. (CVE-2014-4455)

  - A remote code execution issue exists due to improper
    validation of metadata fields in IOSharedDataQueue
    objects. (CVE-2014-4461)");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/en-us/HT6592");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/534005/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV 7.0.2 or later. Note that this update is only
available for 3rd generation and later models.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/20");

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

get_kb_item_or_exit("www/appletv");

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
) audit(AUDIT_WRONG_WEB_SERVER, port, "iTunes on an Apple TV");

fixed_major = "11.1";
fixed_char = "b";
fixed_minor = "37";
fixed_airtunes_version = "211.3";

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
        else audit(AUDIT_LISTEN_NOT_VULN, "AirTunes", airtunes_port, airtunes_version);
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
        if (major <= 9)
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
