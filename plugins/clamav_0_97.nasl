#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51935);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/05/10 19:18:33 $");

  script_cve_id("CVE-2011-1003");
  script_bugtraq_id(46470);
  script_osvdb_id(70937);

  script_name(english:"ClamAV < 0.97 Multiple Vulnerabilities");
  script_summary(english:"Checks response to a clamd VERSION command");

  script_set_attribute(attribute:"synopsis", value:"The remote antivirus service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the clamd antivirus daemon on the remote
host is earlier than 0.97. Such versions reportedly are affected by
multiple vulnerabilities :

  - As-yet unspecified double-free issues involving an error
    path exist in 'libclamav/vba_extract.c' and
    'shared/cdiff.c'. (Bug 2486 and report from
    <mt*debian.org>)

  - 'libclamav/pdf.c' may miss detection. (Bug 2455)

  - Multiple as-yet unspecified error path leaks exit in
    'clamav-milter/whitelist.c', 'clamscan/manager.c', and
    'libclamav/sis.c'. (Report from <mt*debian.org>)");
  script_set_attribute(attribute:"see_also", value:"http://blog.clamav.net/2011/02/clamav-097-has-been-released.html");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vrtadmin/clamav-devel/blob/master/ChangeLog");
  script_set_attribute(attribute:"solution", value:"Upgrade to ClamAV 0.97 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/10");

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

if (ver[0] == 0 && ver[1] < 97)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 0.97\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The host is not affected since ClamAV version " + version + " is installed.");
