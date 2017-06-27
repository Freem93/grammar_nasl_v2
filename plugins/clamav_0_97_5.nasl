#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59726);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/05/10 19:18:33 $");

  script_cve_id(
    "CVE-2012-1457",
    "CVE-2012-1458",
    "CVE-2012-1459"
  );
  script_bugtraq_id(52610, 52611, 52623);
  script_osvdb_id(80408, 80473);

  script_name(english:"ClamAV < 0.97.5 Multiple Vulnerabilities");
  script_summary(english:"Checks response to a clamd VERSION command");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote antivirus service is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the ClamAV clamd antivirus daemon on the
remote host is earlier than 0.97.5 and is, therefore, potentially
affected by the following vulnerabilities :

  - Errors exist related to the 'TAR' file parser that
    can allow malware detection to be bypassed when
    handling such files containing a length field having
    certain values. (CVE-2012-1457, CVE-2012-1459)

  - An error exists related to the 'CHM' file parser that
    can allow malware detection to be bypassed when
    handling such files containing a crafted reset interval
    in the 'LZXC' header. (CVE-2012-1458)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://blog.clamav.net/2012/06/clamav-0975-has-been-released.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/vrtadmin/clamav-devel/blob/master/ChangeLog"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to ClamAV 0.97.5 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.clamav.net/show_bug.cgi?id=4625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.clamav.net/show_bug.cgi?id=4626"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.clamav.net/show_bug.cgi?id=4627"
  );

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:clamav:clamav");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("clamav_detect.nasl");
  script_require_keys("Antivirus/ClamAV/version", "Settings/ParanoidReport");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Antivirus/ClamAV/version");
port = get_service(svc:"clamd", default:3310, exit_on_fail:TRUE);

# nb: banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Check the version number.
#
# nb: versions like 0.94rc1 are possible.
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] == 0 && ver[1] < 97) ||
  (ver[0] == 0 && ver[1] == 97 && ver[2] < 5)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 0.97.5\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "ClamAV", port, version);
