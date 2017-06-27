#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73613);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/19 18:10:51 $");

  script_cve_id("CVE-2014-0160", "CVE-2014-2735");
  script_bugtraq_id(66690, 66936);
  script_osvdb_id(105465, 105969);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");

  script_name(english:"WinSCP Heartbeat Information Disclosure (Heartbleed)");
  script_summary(english:"Checks version of WinSCP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The WinSCP program installed on the remote host is version 4.x later
than 4.3.7, 5.x later than 5.0.6 and prior to 5.5.3. It is, therefore,
affected by the following vulnerabilities :

  - An out-of-bounds read error, known as the 'Heartbleed
    Bug', exists related to handling TLS heartbeat
    extensions that allow an attacker to obtain sensitive
    information such as primary key material, secondary key
    material, and other protected content. (CVE-2014-0160)

  - An error exists related to X.509 certificates, FTP
    with TLS, and host validation that allows an attacker to
    spoof a server and obtain sensitive information.
    (CVE-2014-2735)");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2014/Apr/90");
  script_set_attribute(attribute:"see_also", value:"http://winscp.net/tracker/show_bug.cgi?id=1151");
  script_set_attribute(attribute:"see_also", value:"http://winscp.net/tracker/show_bug.cgi?id=1152");
  script_set_attribute(attribute:"see_also", value:"http://winscp.net/eng/docs/history#5.5.3");
  script_set_attribute(attribute:"see_also", value:"http://heartbleed.com/");
  script_set_attribute(attribute:"see_also", value:"http://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to WinSCP version 5.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:winscp:winscp");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("winscp_installed.nbin");
  script_require_keys("installed_sw/WinSCP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'WinSCP';
fixed_version = '5.5.3';

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

version = install['version'];
path = install['path'];

if (
  # 4.x later than 4.3.7
  (version =~ "^4\." && ver_compare(ver:version, fix:"4.3.7", strict:FALSE) > 0) ||
  # 5.0.6 > 5.x < 5.5.0
  (version =~ "^5\.[0-4]\." && ver_compare(ver:version, fix:"5.0.6", strict:FALSE) > 0) ||
  # 5.5.x < 5.5.3
  (version =~ "^5\.5\." && ver_compare(ver:version, fix:"5.5.3.4193", strict:FALSE) < 0)
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed versions    : ' + fixed_version + 
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
