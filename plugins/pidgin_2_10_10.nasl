#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78689);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/10/27 16:09:20 $");

  script_cve_id(
    "CVE-2014-3694",
    "CVE-2014-3695",
    "CVE-2014-3696",
    "CVE-2014-3697",
    "CVE-2014-3698"
  );
  script_bugtraq_id(70701, 70702, 70703, 70704, 70705);
  script_osvdb_id(113631, 113632, 113633, 113634, 113635);

  script_name(english:"Pidgin < 2.10.10 Multiple Vulnerabilities");
  script_summary(english:"Performs a version check.");

  script_set_attribute(attribute:"synopsis", value:
"An instant messaging client installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Pidgin installed on the remote host is a version prior
to 2.10.10. It is, therefore, affected by the following
vulnerabilities :

  - An error exists in the included libpurple library
    related the SSL Basic Constraints extension and
    Certificate Authority (CA) verification that allows
    intermediate certificates to be trusted as a CA.
    (CVE-2014-3694)

  - An error exists in the included libpurple library
    related to emoticon handling that allows an attacker to
    crash the application. (CVE-2014-3695)

  - An error exists in the included libpurple library
    related to 'Groupwise' message handling and UI memory
    management that allows an attacker to crash the
    application. (CVE-2014-3696)

  - An error exists related to handling 'untar' operations
    on 'smiley themes' that allows arbitrary file
    overwrites. This issue only affects installs on
    Microsoft Windows. (CVE-2014-3697)

  - An error exists in the included libpurple library
    related to handling XMPP messages that allows an
    attacker to obtain arbitrary memory contents.
    (CVE-2014-3698)");
  script_set_attribute(attribute:"see_also", value:"https://developer.pidgin.im/wiki/ChangeLog#version2.10.1010222014");
  script_set_attribute(attribute:"see_also", value:"http://pidgin.im/news/security/?id=86");
  script_set_attribute(attribute:"see_also", value:"http://pidgin.im/news/security/?id=87");
  script_set_attribute(attribute:"see_also", value:"http://pidgin.im/news/security/?id=88");
  script_set_attribute(attribute:"see_also", value:"http://pidgin.im/news/security/?id=89");
  script_set_attribute(attribute:"see_also", value:"http://pidgin.im/news/security/?id=90");
  script_set_attribute(attribute:"solution", value:"Upgrade to Pidgin 2.10.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pidgin:pidgin");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pidgin:libpurple");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("pidgin_installed.nasl");
  script_require_keys("installed_sw/Pidgin", "SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

# Future proof - ensure this is Windows
get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "Pidgin";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];

fixed_version = '2.10.10';

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path               : ' + path +
      '\n  Installed version  : ' + version +
      '\n  Fixed version      : ' + fixed_version + 
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
