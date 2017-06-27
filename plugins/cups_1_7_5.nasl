#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77149);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/04 18:02:14 $");

  script_cve_id("CVE-2014-3537", "CVE-2014-5029", "CVE-2014-5030", "CVE-2014-5031");
  script_bugtraq_id(68788, 68842, 68846, 68847);
  script_osvdb_id(109070);

  script_name(english:"CUPS 1.7.x < 1.7.5 'get_file' Function Symlink Handling Info Disclosure");
  script_summary(english:"Checks the CUPS server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote print service is potentially affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host is 1.7.x prior to 1.7.5. It is, therefore, potentially affected
by an information disclosure vulnerability that was incompletely
corrected by the fix for CVE-2014-3537.

A flaw exists in the 'get_file' function within the file
'scheduler/client.c' regarding the handling of symlinks. This could
allow a local attacker to cause normally protected files to be
accessible via the web interface.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # Blog
  script_set_attribute(attribute:"see_also", value:"https://cups.org/blog.php?L725");
  # Bug
  script_set_attribute(attribute:"see_also", value:"https://cups.org/str.php?L4455");
  # List
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/220");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to CUPS version 1.7.5 or later, or apply the vendor
patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:cups");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cups_1_3_5.nasl");
  script_require_keys("www/cups", "Settings/ParanoidReport");
  script_require_ports("Services/www", 631);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:631, embedded:TRUE);
get_kb_item_or_exit("www/"+port+"/cups/running");

version = get_kb_item_or_exit("cups/"+port+"/version");
source  = get_kb_item_or_exit("cups/"+port+"/source");

if (version =~ "^(1|1\.7)($|[^0-9br.])") audit(AUDIT_VER_NOT_GRANULAR, "CUPS", port, version);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Affected :
# 1.7.x < 1.7.5
if (
  version =~ "^1\.7\.[0-4]($|[^0-9.])" ||
  version =~ "^1\.7(rc|b)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.7.5' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "CUPS", port, version);
