#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55905);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/10 19:18:33 $");

  script_cve_id("CVE-2011-2721");
  script_bugtraq_id(48891);
  script_osvdb_id(74181);
  script_xref(name:"Secunia", value:"45382");

  script_name(english:"ClamAV < 0.97.2 'cli_hm_scan' Denial of Service");
  script_summary(english:"Checks response to a clamd VERSION command");

  script_set_attribute(attribute:"synopsis", value:
"The remote antivirus service is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the ClamAV clamd antivirus daemon on the
remote host is earlier than 0.97.2. As such, it is potentially
affected by a denial of service vulnerability.

An off-by-one error exists in the 'cli_hm_scan' function in the file
'libclamav/matcher-hash.c' that can be exploited by a specially
crafted message causing the clamd daemon to crash.");
  script_set_attribute(attribute:"see_also", value:"http://blog.clamav.net/2011/07/clamav-0972-is-now-available.html");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vrtadmin/clamav-devel/blob/master/ChangeLog");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.clamav.net/show_bug.cgi?id=2818");
  script_set_attribute(attribute:"solution", value:"Upgrade to ClamAV 0.97.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:clamav:clamav");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("clamav_detect.nasl");
  script_require_keys("Antivirus/ClamAV/version", "Settings/ParanoidReport");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# nb: banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

version = get_kb_item_or_exit("Antivirus/ClamAV/version");
port = get_service(svc:"clamd", default:3310, exit_on_fail:TRUE);

# Check the version number.
#
# nb: versions like 0.94rc1 are possible.
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] == 0 && ver[1] < 97)
  ||
  (ver[0] == 0 && ver[1] == 97 && ver[2] < 2)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 0.97.2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The host is not affected since ClamAV version " + version + " is installed.");
