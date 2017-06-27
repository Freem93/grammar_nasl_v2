#TRUSTED 24b2845490e48b7cf9fd4b9646350ce158cffa17774e619939aeb70d77e025e82bb21a894bdf1b4cb7d6ab46509e85753d35d1ccbe528d1641277b80454ad5741acfd5aedf84132480eda10469c8fc7e5152207846b27cb8d603471fcc48a25f52c928d87f5dfa33c1e3a5c638a9f4cb260226222f65796970d867d865f1f42d10650a15cd147f01a8a2939d1d3203e32662785018fe63e789ac8b06303727bc2990005767c96d8f3f52bdf83d8c0686a8c7bdb1b03ac70b401d23e0b086f3ccea4d17458d0b7d232bf0e98b199404b812f06aab99dbd43e04e67a2441438d6b638327303520075e248eaa6e92f93079c73f406ec08ef789b7551e10d2cf509ed33ce7a20145d5992bfd942da1e5ba5dc2bf13ef341fdf6d99b81801a82677d4b44e29c1d26ff0ed2b314e75e68abb675ceec1e144684b9844b89b6c34b67525e197f9d64298533e46bb39709ad50a16b3eb517d47dc2b0322b34a47a1300a72b677f374269653108cf821a18b5922c06a1dafaf3c65be8353b3936ea7d62088e9b6e79d2edd9e73c1c4e95648fbb957bfeeb591080e94ce3d22d7527038f166fc412786e3c78ff731be31bf5e0792787248ebf105c123cb52937e00bd889e35e7765f79b774febb66fab54d18189d758ce8c76455395f71f38a37e893da0b51d95b8ca2a9ff5a146666d88e716fdd7ce31d4fa8c0957304d2be453f79a7edf4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93655);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/10/18");

  script_cve_id("CVE-2016-5309", "CVE-2016-5310");
  script_bugtraq_id(92866, 92868);
  script_osvdb_id(144639, 144640);
  script_xref(name:"IAVA", value:"2016-A-0256");

  script_name(english:"Symantec Protection Engine 7.0.x < 7.0.5 HF02 / 7.5.x < 7.5.5 HF01 / 7.8.x < 7.8.0 HF03 Multiple DoS (SYM16-015) (Linux)");
  script_summary(english:"Checks the version of Symantec Protection Engine.");

  script_set_attribute(attribute:"synopsis", value:
"A security application installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Protection Engine (SPE) installed on the
remote Linux host is 7.0.x prior to 7.0.5 hotfix 02, 7.5.x prior to
7.5.5 hotifx 01, or 7.8.x prior to 7.8.0 hotifx 03. It is, therefore,
affected by multiple denial of service vulnerabilities :

  - A denial of service vulnerability exists in the
    decomposer engine due to an out-of-bounds read error
    that occurs when decompressing RAR archives. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted RAR file, to crash the application.
    (CVE-2016-5309)

  - A denial of service vulnerability exists in the
    decomposer engine due to memory corruption issue that
    occurs when decompressing RAR archives. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted RAR file, to crash the application.
    (CVE-2016-5310)");
  # https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160919_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4125a0d");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/en_US/article.INFO3791.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Protection Engine (SPE) version 7.0.5 HF02 / 7.5.5
HF01 / 7.8.0 HF03 or later per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:protection_engine");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_protection_engine.nbin");
  script_require_keys("installed_sw/Symantec Protection Engine");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");

app = 'Symantec Protection Engine';
port = NULL;
function check_hf(path)
{
  local_var cmd, ret, buf, match, ver;
  local_var line, matches, vuln;

  vuln = FALSE;
  cmd = "cat -v " + path + "/bin/libdec2.so";

  if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

  port = kb_ssh_transport();
  if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

  ret = ssh_open_connection();
  if (!ret) exit(1, 'ssh_open_connection() failed.');


  buf = ssh_cmd(cmd:cmd);
  if(!empty_or_null(buf)){
    match = eregmatch(pattern:"Decomposer\^@(\d\.\d\.\d\.\d)",string:buf);
    ver = match[1];
    if(ver_compare(ver:ver, fix:"5.4.7.5", strict:FALSE) < 0) vuln = TRUE;
  }
  else audit(AUDIT_UNKNOWN_APP_VER, "Symantec Protection Engine: Decomposer Engine");
  return vuln;
}

install = get_single_install(app_name:app);
version = install["version"];
path = install["path"];
path = chomp(path);

fix = NULL;

if (version =~ "^7\.0\.[0-9.]+$")
{
  if (
    version =~ "^7\.0\.5\." &&
    check_hf(path:path)
  ) fix = "7.0.5.x with HF02 applied";

  if (version =~ "^7\.0\.[0-4]\.")
    fix = "7.0.5.x with HF02 applied";
}
else if (version =~ "^7\.5\.[0-9.]+$")
{
  if (
    version =~ "^7\.5\.5\." &&
    check_hf(path:path)
  ) fix = "7.5.5.x with HF01 applied";

  if (version =~ "^7\.5\.[0-4]\.")
    fix = "7.5.5.x with HF01 applied";
}
else if (version =~ "^7\.8\.[0-9.]+$")
{
  if (
    version =~ "^7\.8\.0\." &&
    check_hf(path:path)
  ) fix = "7.8.0.x with HF03 applied";
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

if (!empty_or_null(fix))
{
  report = report_items_str(
    report_items:make_array(
      "Path", path,
      "Installed version", version,
      "Fixed version", fix
    ),
    ordered_fields:make_list("Path", "Installed version", "Fixed version")
  );

  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
