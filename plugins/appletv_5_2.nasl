#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64456);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/01/28 15:42:43 $");

  script_cve_id("CVE-2012-2619", "CVE-2013-0964");
  script_bugtraq_id(56184, 57595);
  script_osvdb_id(86688, 89659);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-01-28-2");
  script_xref(name:"CERT", value:"160027");
  script_xref(name:"EDB-ID", value:"22739");

  script_name(english:"Apple TV < 5.2 Multiple Vulnerabilities");
  script_summary(english:"Checks version in banner");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote Apple TV 2nd generation or later
device is prior to 5.2. It is, therefore, reportedly affected by
several vulnerabilities :

  - Failure to properly validate that the user-mode pointer
    and length passed to the copyin and copyout functions
    could allow a user-mode process to directly access
    kernel memory if the length is smaller than one page.
    (CVE-2013-0964)

  - An out-of-bounds read error in the Broadcom BCM4325 /
    BCM4329 firmware could allow a remote attacker on the
    same Wi-Fi network to cause an unexpected system
    termination by sending a specially crafted RSN (802.11i)
    information element. (CVE-2012-2619)");
  # http://www.coresecurity.com/content/broadcom-input-validation-BCM4325-BCM4329
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8ddc219");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5643");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Jan/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525478/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple TV 5.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/04");

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

pat = "^DAAP-Server: iTunes/([0-9][0-9.]+)[a-z]([0-9]+) \((Mac )?OS X\)";
if (
  "DAAP-Server: iTunes/" >< banner &&
  !egrep(pattern:pat, string:banner)
) exit(0, "The web server listening on port "+port+" does not appear to be from iTunes on an Apple TV.");


fixed_major = "11.0.1";
fixed_minor = "1";

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
  if (report_verbosity > 0) security_warning(port:0, extra:report);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
