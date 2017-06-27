#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92660);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/16 21:57:55 $");

  script_osvdb_id(142154);

  script_name(english:"LastPass Firefox Extension 4.0 < 4.1.21a Message Hijacking");
  script_summary(english:"Checks the version of the LastPass Firefox extension.");

  script_set_attribute(attribute:"synopsis", value:
"A password manager installed on the remote host is affected by a
remote message hijacking vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the LastPass Firefox extension installed on
the remote Windows host is 4.0.x prior to 4.1.21a. It is, therefore,
affected by a message hijacking vulnerability due to improper
validation of messages sent between the extension and a privileged
iframe. An unauthenticated, remote attacker can exploit this issue, by
convincing a user into loading a specially crafted web page that
programmatically clicks a LastPass modified input element, to take
full control of the LastPass extension, including creating and
deleting files, executing scripts, and disclosing passwords.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.chromium.org/p/project-zero/issues/detail?id=884");
  script_set_attribute(attribute:"see_also", value:"https://blog.lastpass.com/2016/07/lastpass-security-updates.html/");
  script_set_attribute(attribute:"see_also", value:"http://thehackernews.com/2016/07/lastpass-password-manager.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LastPass Firefox extension version 4.1.21a or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:lastpass:lastpass");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("win_firefox_browser_addons.nbin");
  script_require_keys("Browser/Firefox/Extension");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("smb_hotfixes_fcheck.inc");
include("browser.inc");

ff = "Mozilla Firefox";
lpff = "LastPass Firefox extension";

# only the Firefox extension is affected
get_install_count(app_name:ff, exit_if_zero:TRUE);

installs = get_browser_addons(browser:"Firefox", type:"Extension", name:"LastPass");
installs = installs['addons'];

if (max_index(installs) == 0)
  audit(AUDIT_NOT_INST, lpff);

# branch on detected installs to stay sane
install      = branch(installs);
install_path = install['path'];
disp_ver     = install['version'];

# strip trailing characters like the a in 4.1.21a, as it is just used
# to indicated this is a beta version
version = eregmatch(pattern:"^([0-9.]+)", string:disp_ver);
version = version[1];

# only 4.x is affected
if (version !~ "^4\.")
  audit(AUDIT_INST_PATH_NOT_VULN, lpff, disp_ver, install_path);

fix = "4.1.21";
disp_fix = "4.1.21a";
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item('SMB/transport');
  if (!port)
    port = 445;

  order = make_list("Extension path", "Extension version", "Fixed version");
  report = make_array(
    order[0], install_path,
    order[1], disp_ver,
    order[2], disp_fix
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, lpff, disp_ver, install_path);
