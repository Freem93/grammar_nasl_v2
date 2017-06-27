#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90765);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:15:08 $");

  script_osvdb_id(137160);

  script_name(english:"Core FTP Server < 1.2 Build 588 32-bit Unspecified Overflow Vulnerability");
  script_summary(english:"Checks the version of Core FTP Server.");

  script_set_attribute(attribute:"synopsis", value:
"The FTP server running on the remote host is affected by an
unspecified overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The 32-bit version of Core FTP Server running on the remote host is
prior to 1.2 build 588. It is, therefore, affected by an overflow
condition due to a failure to properly validate user-supplied input
when using FTP, FTPS, or SSL. An unauthenticated, remote attacker can
exploit this to impact the confidentiality, integrity, or availability
of the system. No other details are provided. Note that the 64-bit
version is not affected.");
  # http://coreftp.com/forums/viewtopic.php?t=4022520&sid=242e0acab39b0903f4176a12913e10ba
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?006bcb64");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Core FTP version 1.2 build 588 (32-bit) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:coreftp:coreftp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("coreftp_server_detect.nbin");
  script_require_ports("Services/ftp", 21);
  script_require_keys("installed_sw/Core FTP Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname = 'Core FTP Server';
install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);

port = install["path"];
source = install["version_source"];
version_build = install["version_build"];
fullver = install["fullversion"];

fix = "1.2.588";
if (ver_compare(ver:fullver, fix:fix, strict:FALSE) == -1)
{
  # report if this is a 32 bit build or we are paranoid and not cpu info is available
  if ("32-bit" >< version_build || (report_paranoia > 1 && "64-bit" >!< version_build))
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version_build +
      '\n  Fixed version     : 1.2 Build 588 32-bit' +
      '\n';
    security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  }
  else if ("64-bit" >< version_build) audit(AUDIT_LISTEN_NOT_VULN, 'Core FTP Server', port, version_build);
  else audit(AUDIT_VER_NOT_GRANULAR, appname, port, version_build);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'Core FTP Server', port, version_build);
