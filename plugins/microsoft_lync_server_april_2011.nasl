#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68880);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/07/10 20:06:33 $");

  script_bugtraq_id(48235);
  script_osvdb_id(73380);
  script_xref(name:"IAVB", value:"2011-B-0074");

  script_name(english:"Microsoft Lync Server 2010 reachLocale Parameter XSS");
  script_summary(english:"Determines if the patch is needed and missing");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application on the remote host has a cross-site scripting
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the version of Web
Components Server (a component of Microsoft Lync 2010) has a cross-site
scripting vulnerability.  Input passed to the 'reachLocale' parameter of
ReachJoin.aspx is not properly sanitized.  An attacker could exploit
this by tricking a user into requesting a specially crafted URL,
resulting in arbitrary script code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.foofus.net/?p=363");
  script_set_attribute(attribute:"see_also", value:"http://www.foofus.net/?page_id=372");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2500441");
  script_set_attribute(
    attribute:"solution",
    value:
"Install the Lync Server 2010, Web Components Server April 2011 update
(KB2500441) or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_server:2010");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("microsoft_lync_server_installed.nasl");
  script_require_keys("installed_sw/Microsft Lync");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

# Only Lync Server 2010 is affected.  Any other versions or incarnations
# of this software should be ignored
appname = "Microsoft Lync";

get_install_count(app_name:appname, exit_if_zero:TRUE);
install = get_install_count(app_name:appname);

version = install["version"];
path    = install["path"];
product = install["Product"];

if (isnull(product) || "Server 2010" >!< product)
  audit(AUDIT_INST_PATH_NOT_VULN, 'Lync Server', product);

share = hotfix_path2share(path:path);
if (!is_accessible_share(share:share))
  audit(AUDIT_SHARE_FAIL, share);

path = hotfix_append_path(path:path, value:"Web Components\Reach\Ext\bin");
if (hotfix_is_vulnerable(path:path, file:"Microsoft.Rtc.Internal.ReachJoin.dll", version:"4.0.7577.139", min_version:"4.0.7577.0"))
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

