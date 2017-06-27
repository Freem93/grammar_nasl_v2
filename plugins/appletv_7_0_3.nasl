#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81145);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/01/28 15:42:43 $");

  script_cve_id(
    "CVE-2014-3192",
    "CVE-2014-4455",
    "CVE-2014-4459",
    "CVE-2014-4465",
    "CVE-2014-4466",
    "CVE-2014-4468",
    "CVE-2014-4469",
    "CVE-2014-4470",
    "CVE-2014-4471",
    "CVE-2014-4472",
    "CVE-2014-4473",
    "CVE-2014-4474",
    "CVE-2014-4475",
    "CVE-2014-4476",
    "CVE-2014-4477",
    "CVE-2014-4479",
    "CVE-2014-4480",
    "CVE-2014-4481",
    "CVE-2014-4483",
    "CVE-2014-4484",
    "CVE-2014-4485",
    "CVE-2014-4486",
    "CVE-2014-4487",
    "CVE-2014-4488",
    "CVE-2014-4489",
    "CVE-2014-4491",
    "CVE-2014-4492",
    "CVE-2014-4495",
    "CVE-2014-4496"
  );
  script_bugtraq_id(
    70273,
    71140,
    71144,
    71438,
    71439,
    71442,
    71444,
    71445,
    71449,
    71451,
    71459,
    71461,
    71462,
    72327,
    72329,
    72330,
    72331,
    72334
  );
  script_osvdb_id(
    112753,
    114726,
    114735,
    115345,
    115346,
    115347,
    115348,
    115349,
    115350,
    115351,
    115352,
    115353,
    115354,
    117621
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-01-27-1");

  script_name(english:"Apple TV < 7.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version in the banner.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote Apple TV device is a version prior
to 7.0.3. It is, therefore, affected by the following
vulnerabilities :

  - Multiple memory corruption issues exist, related to the
    included version of WebKit, that allow application
    crashes or arbitrary code execution. (CVE-2014-3192,
    CVE-2014-4459, CVE-2014-4466, CVE-2014-4468,
    CVE-2014-4469, CVE-2014-4470, CVE-2014-4471,
    CVE-2014-4472, CVE-2014-4473, CVE-2014-4474,
    CVE-2014-4475, CVE-2014-4476, CVE-2014-4477,
    CVE-2014-4479)

  - A state management issue exists due to improperly
    handling overlapping segments in Mach-O executable
    files. A local user can exploit this issue to execute
    unsigned code. (CVE-2014-4455)

  - A security bypass issue exists due to improper
    validation of SVG files loaded in an IMG element. An
    attacker can load a CSS of cross-origin resulting in
    information disclosure. (CVE-2014-4465)

  - An issue exists due to the symbolic linking performed
    by the 'afc' command which allows an attacker to
    access arbitrary files on the system. (CVE-2014-4480)

  - An integer overflow issue exists due to improper bounds
    checking when processing PDF files. (CVE-2014-4481)

  - A buffer overflow issue exists due to improper bounds
    checking when processing fonts in PDF files.
    (CVE-2014-4483)

  - A memory corruption issue exists due to improper bounds
    checking when processing '.dfont' files.
    (CVE-2014-4484)

  - A buffer overflow issue exists due to improper bounds
    checking when processing XML files. (CVE-2014-4485)

  - A null pointer dereference issue exists due to the
    handling of resource lists in the IOAcceleratorFamily
    kernel extension. (CVE-2014-4486)

  - A buffer overflow issue exists due to improper size
    validation in the IOHIDFamily. (CVE-2014-4487)

  - A validation issue exists due to the handling of
    resource queue metadata in the IOHIDFamily kernel
    extension. (CVE-2014-4488)

  - A null pointer dereference issue exists due to the
    handling of event queues in the IOHIDFamily kernel
    extension. (CVE-2014-4489)

  - An information disclosure issue exists due to the
    handling of APIs related to kernel extensions in which
    kernel addresses may be revealed. An attacker can
    leverage this to bypass ASLR protections.
    (CVE-2014-4491)

  - Multiple type confusion issues exists due to improper
    type checking during interprocess communication in the
    network daemon (networkd). (CVE-2014-4492)

  - An issue exists due to improper checking of shared
    memory permissions in the kernel shared memory
    subsystem. (CVE-2014-4495)

  - An information disclosure issue exists due to
    mach_port_kobject kernel interface leaking kernel
    addresses and heap permutation values. An attacker can
    leverage this to bypass ASLR protections.
    (CVE-2014-4496)

Note that arbitrary code execution is possible with the above issues
assigned CVE-2014-4481 through CVE-2014-4489, CVE-2014-4492, and
CVE-2014-4495.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/en-us/HT204246");
  # http://lists.apple.com/archives/security-announce/2015/Jan/msg00000.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9cd82503");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple TV 7.0.3 or later. Note that this update is only
available for 3rd generation and later models.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_tv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("appletv_detect.nasl");
  script_require_keys("www/appletv");
  script_require_ports(3689, 7000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

get_kb_item_or_exit("www/appletv");

# Apple TV 6.0 and later
port = get_http_port(default:7000, dont_exit:TRUE);
item  = "/server-info";

if (!isnull(port))
{
  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : item,
    exit_on_fail:FALSE
  );

  report = NULL;

  if (res[0] =~'^HTTP/[0-9.]+ +200' && !empty_or_null(res[2]))
  {
    url = build_url(port:port, qs:item);

    # Examples: 12B435, 11A470e, etc.
    pat =
      "<key>osBuildVersion</key>\s+<string>([0-9]+)([A-Za-z])([0-9]+)([A-Za-z]+)?</string>";
    matches = pregmatch(pattern:pat, string:res[2], icase:TRUE);

    if (!isnull(matches))
    {
      ver       = matches[1] + matches[2] + matches[3];
      ver_major = int(matches[1]);
      ver_char  = ord(matches[2]);
      ver_minor = int(matches[3]);

      fixed_build = "12B466";
      fixed_major = 12;
      fixed_char  = ord("B");
      fixed_minor = 466;

      if (
        # Major version <= fixed version
        ver_major < fixed_major || ( ver_major == fixed_major &&
          (
            # Value of character <= value of fixed character
            ver_char < fixed_char || ( ver_char == fixed_char &&
              # Minor version < fixed version
              ver_minor < fixed_minor
            )
          )
        )
      )
        report =
          '\n  URL             : ' + url +
          '\n  Installed build : ' + ver +
          '\n  Fixed build     : ' + fixed_build + ' (Apple TV 7.0.3)' +
          '\n';

      else
        audit(AUDIT_HOST_NOT, "affected because it is running build " + ver);
    }
    else
    {
      pat = "<key>srcvers</key>\s+<string>([0-9.]+)</string>";
      matches = pregmatch(pattern:pat, string:res[2], icase:TRUE);
      if (!isnull(matches))
      {
        airplay_ver       = matches[1];
        fixed_airplay_ver = "211.3";

        if (ver_compare(ver:airplay_ver, fix:fixed_airplay_ver, strict:FALSE) < 0)
        {
          report =
            '\n  URL                       : ' + url +
            '\n  Installed AirPlay version : ' + airplay_ver +
            '\n  Fixed AirPlay version     : ' + fixed_airplay_ver +
            '\n';
        }
        else
          audit(AUDIT_HOST_NOT, "affected because it is running AirPlay " + airplay_ver);
      }
    }
  }
}

if (isnull(report))
{
  port = 3689;
  banner = get_http_banner(port:port, broken:TRUE, exit_on_fail:TRUE);
  if ("DAAP-Server: iTunes/" >!< banner && "RIPT-Server: iTunesLib/" >!< banner)
    audit(AUDIT_WRONG_WEB_SERVER, port, 'iTunes');

  pat = "^DAAP-Server: iTunes/([0-9][0-9.]+)([a-z])([0-9]+) \((Mac )?OS X\)";
  matches = egrep(pattern:pat, string:banner);

  if ("DAAP-Server: iTunes/" >< banner && !matches)
    audit(AUDIT_WRONG_WEB_SERVER, port, "iTunes on an Apple TV");

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

if (!empty_or_null(report))
{
  if (report_verbosity > 0) security_hole(port:0, extra:report);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
