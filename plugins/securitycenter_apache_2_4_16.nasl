#TRUSTED a2b694ca116a4107acc0a03ecf8c68781d444513801047c8df388d25b153ba788f5961c4cb08a77ed937838b3dbb77fe11e2f75b025428988bb581dc44bc2c34bbf189f39135e78c3f604648bba36f48a7338f19f86a7dca5da8b79f6635fcc3cc8aec5b2abcc58a58a04ad59e164f1bea169a383145a8d2688d1589887316b97fec7e3af4b82f68fb6fbb1432b34f2b4556a24b1ce41e73da7ae9f4edae7b18ac0410d527fa6feeb83f7ed77bd17ed0ea67eaa0d325fec34e47a6412f816000185d47e6eb63c35019932d89e9f28a06622b815963b8015926910544ccd0033858957dc7cc8e8701e1b3e662fac9be2b7b1a5c0abe3afe85d729a28b9a48dcebc3514137393f6fa0c739ad5433317ca5feaa86fefc01ffade1b8dfaf4b83917b9602435a59298ad44e6774893b1fe5d8d7dd3ab5e7f7701e477dd7e8833a4700c986c3e2a86922a4bf3560264b2885c3466299b9de15c633065f61685858490d435f8c9ef4ba2329271e7328301640ed538ee677f2bf8f6eeff44c95eb4ae418df02eed0cff141916d664077fdddced85d2ecac8012a0b88e6c9f8489dd2e6207195df54375df1da0fdb74ce49b2a917d0c45bd01b65403fcb5a8b821e2680ed3f20546aa0ad2e9baaf1ceda1f0e91bc7176aaa028c4354dc92c3f0d38c556a13c5dc663ebe21fbff90e6dba0d7ae76d4e76daf84b05b044f26e555dc18651fd
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85628);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/03");

  script_cve_id(
    "CVE-2015-3183",
    "CVE-2015-3185"
  );
  script_bugtraq_id(
    75963,
    75965
  );
  script_osvdb_id(
    123122,
    123123
  );

  script_name(english:"Tenable SecurityCenter Multiple Apache Vulnerabilities (TNS-2015-11)");
  script_summary(english:"Checks the version of Apache in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Tenable SecurityCenter application installed on the remote host
contains a bundled version of Apache HTTP Server prior to 2.4.16. It
is, therefore, affected by the following vulnerabilities :

  - A flaw exists in the chunked transfer coding
    implementation in http_filters.c. due to a failure to
    properly parse chunk headers when handling large
    chunk-size values and invalid chunk-extension
    characters. A remote attacker can exploit this, via a
    crafted request, to carry out HTTP request smuggling,
    potentially resulting in cache poisoning or the
    hijacking of credentials. (CVE-2015-3183)

  - A security bypass vulnerability exists due to a failure
    in the ap_some_auth_required() function in request.c to
    consider that a Require directive may be associated with
    an authorization setting instead of an authentication
    setting. A remote attacker can exploit this, by
    leveraging the presence of a module that relies on the
    2.2 API behavior, to bypass intended access restrictions
    under certain circumstances.
    (CVE-2015-3185)

Note that the 4.x version of SecurityCenter is impacted only by
CVE-2015-3183. The 5.x version is impacted by both CVE-2015-3183 and
CVE-2015-3185");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/security/tns-2015-11");
  script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/Announcement2.2.html");
  script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/Announcement2.4.html");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch for version 4.7.1 / 4.8.2 as referenced in
the vendor advisory. Alternatively, upgrade to Tenable SecurityCenter
version 5.0.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_keys("Host/SecurityCenter/Version", "Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

if (! get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

sc_ver = get_kb_item_or_exit("Host/SecurityCenter/Version");

# No patches for SC 4.6
if (! ereg(pattern:"^(4\.[678]|5)\.", string:sc_ver))
  audit(AUDIT_INST_VER_NOT_VULN, "SecurityCenter", sc_ver);

# Depending on the version of SC, the path and fix differ.
sc_path = "";
fix = "";

if (sc_ver =~ "^4\.")
{
  fix = "2.2.31";
  sc_path = "sc4";
}
else if (sc_ver =~ "^5\.")
{
  fix = "2.4.16";
  sc_path = "sc";
}

# Establish running of local commands
if (islocalhost())
{
  if (! defined_func("pread"))
    audit(AUDIT_NOT_DETECT, "pread");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (! sock_g)
    audit(AUDIT_HOST_NOT, "able to connect via the provided SSH credentials.");
  info_t = INFO_SSH;
}

line = info_send_cmd(cmd:"/opt/" + sc_path + "/support/bin/httpd -v");
if (!line)
  audit(AUDIT_UNKNOWN_APP_VER, "Apache (bundled with SecurityCenter)");

pattern = "Server version: Apache/([0-9.]+) ";
match = eregmatch(pattern:pattern, string:line);

if (isnull(match))
  audit(AUDIT_UNKNOWN_APP_VER, "Apache (bundled with SecurityCenter)");

version = match[1];

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report = '\n' +
    '\n  SecurityCenter version        : ' + sc_ver +
    '\n  SecurityCenter Apache version : ' + version +
    '\n  Fixed Apache version          : ' + fix +
    '\n';
  security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Apache (bundled with SecurityCenter)", version);
