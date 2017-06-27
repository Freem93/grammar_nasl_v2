#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51125);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2010-4260", "CVE-2010-4261", "CVE-2010-4479");
  script_bugtraq_id(45152);
  script_osvdb_id(69611, 69612, 69656);
  script_xref(name:"Secunia", value:"42426");

  script_name(english:"ClamAV < 0.96.5 Multiple Vulnerabilities");
  script_summary(english:"Checks response to a clamd VERSION command");

  script_set_attribute(attribute:"synopsis", value:"The remote antivirus service is affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"According to its version, the clamd antivirus daemon on the remote
host is earlier than 0.96.5. Such versions are reportedly affected by
multiple vulnerabilities :

  - Multiple errors exist in the PDF processing functions in
    'libclamav/pdf.c', which could lead to application
    crashes. (Bugs 2358, 2380, 2396)

  - An off-by-one error exists in the handling of icons such
    that a crafted icon may be used to cause an integer
    overflow. (Bug 2344)");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe2848b9");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9a63cb5");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87149641");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?022c6883");
  script_set_attribute(attribute:"see_also", value:"http://freshmeat.net/projects/clamav/releases/325193");
  script_set_attribute(attribute:"solution", value:"Upgrade to ClamAV 0.96.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:clamav:clamav");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("clamav_detect.nasl");
  script_require_keys("Antivirus/ClamAV/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# nb. banner checks of open source software are prone to false-
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
  (
    ver[0] == 0 &&
    (
      ver[1] < 96 ||
      (ver[1] == 96 && ver[2] < 5)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    fixed_version = "0.96.5";

    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The host is not affected since ClamAV version " + version + " is installed.");
