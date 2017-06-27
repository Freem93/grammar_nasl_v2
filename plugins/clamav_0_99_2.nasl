#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93897);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/17 21:38:53 $");

  script_cve_id("CVE-2016-1371", "CVE-2016-1372");
  script_bugtraq_id(93221, 93222);
  script_osvdb_id(144929, 144930);

  script_name(english:"ClamAV < 0.99.2 Multiple libclamav DoS");
  script_summary(english:"Checks the response to a clamd VERSION command.");

  script_set_attribute(attribute:"synopsis", value:
"The antivirus service running on the remote host is affected by
multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the ClamAV clamd antivirus daemon running on
the remote host is prior to 0.99.2. It is, therefore, affected by
multiple vulnerabilities :

  - A denial of service vulnerability exists in the
    libclamav library when handling specially crafted mew
    packer executables. An unauthenticated, remote attacker
    can exploit this, by convincing a user to open a
    specially crafted file, to crash the application.
    (CVE-2016-1371)

  - Multiple denial of service vulnerabilities exist in the
    libclamav library when handling specially crafted 7z
    files. An unauthenticated, remote attacker can exploit
    these, by convincing a user to open a specially crafted
    file, to crash the application. (CVE-2016-1372)");
  script_set_attribute(attribute:"see_also", value:"http://blog.clamav.net/2016/05/clamav-0992-has-been-released.html");
  script_set_attribute(attribute:"see_also", value:"https://foxglovesecurity.com/2016/06/13/finding-pearls-fuzzing-clamav/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ClamAV version 0.99.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:clamav:clamav");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("clamav_detect.nasl");
  script_require_keys("Antivirus/ClamAV/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Antivirus/ClamAV/version");
port    = get_service(svc:"clamd", default:3310, exit_on_fail:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  version =~ "^0\.(\d|[0-8]\d|9[0-8])($|[^0-9])"
  ||
  version =~ "^0.99($|-beta[12]|-rc[12])"
  ||
  version =~ "^0\.99\.[01]($|[^0-9])"
)
{
  security_report_v4(
    port:port,
    severity:SECURITY_WARNING,
    extra:
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 0.99.2' +
      '\n'
  );
}
else audit(AUDIT_LISTEN_NOT_VULN, "ClamAV", port, version);
