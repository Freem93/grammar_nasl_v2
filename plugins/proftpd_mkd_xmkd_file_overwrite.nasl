#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66970);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_cve_id("CVE-2012-6095");
  script_bugtraq_id(57172);
  script_osvdb_id(89051);

  script_name(english:"ProFTPD FTP Command Handling Symlink Arbitrary File Overwrite");
  script_summary(english:"Checks version in the service banner");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by an arbitrary file overwrite
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is using ProFTPD, a free FTP server for Unix and Linux. 
According to its banner, the version of ProFTPD installed on the remote
host earlier than 1.3.4c.  As such, it is potentially affected by a race
condition error that does not securely create temporary files related to
symlinks and newly created directories.  A local, attacker could
leverage this issue to overwrite arbitrary files and elevate privileges. 

Note that Nessus did not actually test for the flaw but has instead
relied on the version in ProFTPD's banner.");
  # https://web.archive.org/web/20160402191530/http://proftpd.org/docs/RELEASE_NOTES-1.3.4c
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5fd455fb");
  script_set_attribute(attribute:"see_also", value:"http://proftpd.org/docs/RELEASE_NOTES-1.3.5rc1");
  script_set_attribute(attribute:"see_also", value:"http://bugs.proftpd.org/show_bug.cgi?id=3841");
  script_set_attribute(attribute:"solution", value:"Upgrade to 1.3.4c / 1.3.5rc1 or apply the patch from the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:proftpd:proftpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_keys("ftp/proftpd", "Settings/ParanoidReport");
  script_require_ports("Services/ftp", 21);
  exit(0);
}


include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if (!banner) audit(AUDIT_NO_BANNER, port);
if ("ProFTPD" >!< banner) audit(AUDIT_NOT_LISTEN, "ProFTPD", port);

matches = eregmatch(string:banner, pattern:"ProFTPD ([0-9a-z.]+) ");
if (!isnull(matches)) version = matches[1];
else audit(AUDIT_SERVICE_VER_FAIL, "ProFTPD", port);

# nb: banner checks of open source software are prone to false-positives
# so we only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ '^1(\\.3)?$') exit(1, "The banner from ProFTPD listening on port "+port+" - "+banner+" - is not granular enough.");

# Affected
# 0.x - 1.3.3x
# 1.3.4x < 1.3.4c (to include rc1 - rc3 and ^1.3.4$
# While the issue is patched in 1.3.5rc1, there is no
# 1.3.5x version before that, therefore nothing to check
if (
  version =~ "^0\." ||
  version =~ "^1\.[0-2]($|\.)" ||
  version =~ "^1\.3\.[0-3]($|[^0-9])" ||
  version =~ "^1\.3\.4($|[ab]$|rc[1-3]$)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + chomp(banner) +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.3.4c / 1.3.5rc1\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
audit(AUDIT_LISTEN_NOT_VULN, "ProFTPD", port, version);
