#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(60111);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_cve_id("CVE-2012-4992");
  script_bugtraq_id(52259);
  script_osvdb_id(79767);
  script_xref(name:"EDB-ID", value:"18555");

  script_name(english:"FlashFXP < 4.2.0.1730 ListIndex TListBox Handling Remote Overflow");
  script_summary(english:"Checks version of FlashFXP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an FTP client that is affected by a buffer
overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of FlashFXP prior to 4.2.0.1730. 
It therefore is reportedly has a buffer overflow vulnerability
involving the TListbox and TComboBox VCL components. 

To exploit the vulnerability remotely, an attacker would need to know
the included filters of the connected client to send large strings. 

Successful exploitation would allow an attacker to execute arbitrary
code within the context of the affected application."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Mar/7");
  # http://www.flashfxp.com/forum/flashfxp/news/15473-flashfxp-4-2-released.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24fb05d4");
  script_set_attribute(attribute:"solution", value:"Upgrade to FlashFXP 4.2.0 (4.2.0.1730) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:flashfxp:flashfxp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("flashfxp_installed.nasl");
  script_require_keys("SMB/FlashFXP/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "SMB/FlashFXP/";
appname = "FlashFXP";

get_kb_item_or_exit(kb_base + 'Installed');

installs = get_kb_list(kb_base + 'Installs/*');
if (isnull(installs)) exit(1, 'The \'' + kb_base + 'Installs KB list is missing.');

info = '';
info2 = '';
vuln = 0;
foreach install (keys(installs))
{
  path = installs[install];
  version = install - (kb_base + 'Installs/');

  fix = '4.2.0.1730';
  if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
  {
    vuln++;
    info += 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
  }
  else info2 += ' and ' + version;
}

if (info)
{
  if (report_verbosity > 0) security_hole(port:get_kb_item('SMB/transport'), extra:info);
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
}

if (info2)
{
  info2 -= ' and ';
  if (' and ' >< info2) be = 'are';
  else be = 'is';

  exit(0, 'The host is not affected since ' + appname + ' ' + info2 + ' ' + be + ' installed.');
}
else exit(1, 'Unexpected error - \'info2\' is empty.');
