#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72662);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/30 23:05:16 $");

  script_cve_id(
    "CVE-2014-1441",
    "CVE-2014-1442",
    "CVE-2014-1443"
  );
  script_bugtraq_id(
    65428,
    65430,
    65432
  );
  script_osvdb_id(
    102966,
    102967,
    102968
  );

  script_name(english:"Core FTP Server < 1.2 Build 515 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Core FTP Server.");

  script_set_attribute(attribute:"synopsis", value:
"The FTP server running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Core FTP running on the remote host is prior to 1.2
build 515. It is, therefore, affected by multiple vulnerabilities :

  - A denial of service vulnerability exists that is
    triggered when handling malformed data after the 'AUTH
    SSL' command. An unauthenticated, remote attacker can
    exploit this to cause an assertion failure, resulting in
    a server crash. (CVE-2014-1441)

  - An information disclosure vulnerability exists due to a
    failure to properly sanitize user-supplied input. An
    authenticated, remote attacker can exploit this, via
    directory traversal using the 'XCRC' command, to gain
    access to arbitrary files. (CVE-2014-1442)

  - An information disclosure vulnerability exists due to
    improper handling of crafted string data by the 'USER'
    command. An authenticated, remote attacker can exploit
    this, via a specially crafted string, to access the
    password for the user that previously logged on.
    (CVE-2014-1443)");
  script_set_attribute(attribute:"see_also", value:"http://coreftp.com/forums/viewtopic.php?t=2985707");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2014/Feb/39");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Core FTP version 1.2 build 515 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:coreftp:coreftp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

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

fix = "1.2.515";
if (ver_compare(ver:fullver, fix:fix, strict:FALSE) == -1)
{
  report =
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version_build +
    '\n  Fixed version     : 1.2 Build 515' +
    '\n';
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'Core FTP Server', port, version_build);
