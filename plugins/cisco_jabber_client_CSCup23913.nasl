#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76129);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2014-0076", "CVE-2014-0224", "CVE-2014-3470");
  script_bugtraq_id(66363, 67898, 67899);
  script_osvdb_id(104810, 107729, 107731);
  script_xref(name:"CERT", value:"978508");

  script_name(english:"Cisco Windows Jabber Client Multiple Vulnerabilities in OpenSSL");
  script_summary(english:"Checks Jabber version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Cisco Jabber installed that is known
to be affected by multiple OpenSSL related vulnerabilities :

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    could allow nonce disclosure via the 'FLUSH+RELOAD'
    cache side-channel attack. (CVE-2014-0076)

  - An unspecified error exists that could allow an
    attacker to cause usage of weak keying material
    leading to simplified man-in-the-middle attacks.
    (CVE-2014-0224)

  - An unspecified error exists related to anonymous ECDH
    ciphersuites that could allow denial of service
    attacks. Note this issue only affects OpenSSL TLS
    clients. (CVE-2014-3470)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140605-openssl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5539aa9d");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:"No known fixed versions have been released.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:jabber");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies('cisco_jabber_client_installed.nbin');
  script_require_keys('SMB/Cisco Jabber for Windows/Installed');
  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

appname = "Cisco Jabber for Windows";
get_kb_item_or_exit("SMB/" + appname + "/Installed");

kb_installs = get_kb_list_or_exit("SMB/" + appname + "/*/Version");

# If only one install, don't bother branching
if (max_index(keys(kb_installs)) == 1)
{
  item = keys(kb_installs);
  kb_entry = item[0];
}
else
  kb_entry = branch(keys(kb_installs));

version = get_kb_item_or_exit(kb_entry);
kb_base = kb_entry - "/Version";
path = get_kb_item_or_exit(kb_base + "/Path");

ver_ui = get_kb_item(kb_base + "/Ver_UI");

if (ver_ui) report_version = ver_ui + ' (' + version + ')';
else report_version = version;

# from Cisco: "we expect this issue to be resolve in version 10.5 of jabber for windows."
# therefore, I'm flagging all current and past releases as vulnerable
# < 9.2.x
# 9.2.x <= 9.2(6)
# 9.6.x <= 9.6(1)
# 9.7.x <= 9.7(2)

if (
  ver_compare(ver:version, fix:"9.2", strict:FALSE) <= 0 ||
  version =~ "^9\.2\.[0-6]($|\.)" ||
  version =~ "^9\.6\.[012]($|\.)" ||
  version =~ "^9\.7\.[012]($|\.)"
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + report_version +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, report_version, path);
