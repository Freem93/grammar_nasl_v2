#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77822);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/11 19:58:29 $");

  script_cve_id(
    "CVE-2011-2391",
    "CVE-2013-6663",
    "CVE-2014-1384",
    "CVE-2014-1385",
    "CVE-2014-1387",
    "CVE-2014-1388",
    "CVE-2014-1389",
    "CVE-2014-4357",
    "CVE-2014-4364",
    "CVE-2014-4369",
    "CVE-2014-4371",
    "CVE-2014-4372",
    "CVE-2014-4373",
    "CVE-2014-4375",
    "CVE-2014-4377",
    "CVE-2014-4378",
    "CVE-2014-4379",
    "CVE-2014-4380",
    "CVE-2014-4381",
    "CVE-2014-4383",
    "CVE-2014-4388",
    "CVE-2014-4389",
    "CVE-2014-4404",
    "CVE-2014-4405",
    "CVE-2014-4407",
    "CVE-2014-4408",
    "CVE-2014-4410",
    "CVE-2014-4411",
    "CVE-2014-4412",
    "CVE-2014-4413",
    "CVE-2014-4414",
    "CVE-2014-4415",
    "CVE-2014-4418",
    "CVE-2014-4419",
    "CVE-2014-4420",
    "CVE-2014-4421",
    "CVE-2014-4422"
  );
  script_bugtraq_id(
    62531,
    65930,
    69223,
    69881,
    69882,
    69903,
    69911,
    69912,
    69913,
    69915,
    69919,
    69921,
    69923,
    69924,
    69927,
    69928,
    69929,
    69930,
    69931,
    69934,
    69938,
    69939,
    69941,
    69942,
    69944,
    69946,
    69947,
    69948,
    69950,
    69966,
    69970,
    69973
  );
  script_osvdb_id(
    97438,
    103939,
    110033,
    110034,
    110035,
    110036,
    110037,
    111643,
    111652,
    111653,
    111654,
    111655,
    111656,
    111657,
    111660,
    111661,
    111667,
    111669,
    111670,
    111671,
    111672,
    111673,
    111674,
    111676,
    111677,
    111678,
    111679,
    111680,
    111681,
    111682,
    111683,
    111684
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-09-17-2");

  script_name(english:"Apple TV < 7 Multiple Vulnerabilities");
  script_summary(english:"Checks the version in the banner.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote Apple TV device is a version prior
to 7. It is, therefore, affected by multiple vulnerabilities, the most
serious of which can result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6442");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/533468/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV 7 or later. Note that this update is only
available for 3rd generation and later models.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mac OS X IOKit Keyboard Driver Root Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/24");

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
fixed_airtunes_version = "210.98";

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
