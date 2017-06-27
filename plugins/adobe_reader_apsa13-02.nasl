# @DEPRECATED@
#
# This plugin has been deprecated. Use adobe_reader_apsb13-07.nasl (plugin #64786) instead.
#
# Disabled on 2013/02/21.
#

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64645);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/05/18 02:53:55 $");

  script_cve_id("CVE-2013-0640", "CVE-2013-0641");
  script_bugtraq_id(57931, 57947);
  script_osvdb_id(90169, 90170);

  script_name(english:"Adobe Reader <= 11.0.1 / 10.1.5 / 9.5.3 Multiple Vulnerabilities (APSA13-02)");
  script_summary(english:"Checks version of Adobe Reader and registry key");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Adobe Reader on the remote Windows host is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Adobe Reader installed on the remote host is equal or
prior to 11.0.1 / 10.1.5 / 9.5.3, or is 11.0.1 and missing a workaround
fix.  Therefore, it is affected by two unspecified remote code execution
vulnerabilities."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/advisories/apsa13-02.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Adobe Reader 11.0.1 and apply the workaround described in
the advisory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("adobe_reader_installed.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Acroread/Version", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Use adobe_reader_apsb13-07.nasl (plugin #64786) instead.");


include('audit.inc');
include('global_settings.inc');
include("smb_hotfixes.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

info =  '';
info2 = '';
vuln = 0;
vers = get_kb_list('SMB/Acroread/Version');
if (isnull(vers)) audit(AUDIT_KB_MISSING, 'SMB/Acroread/Version');

registry_init();
mitigation = FALSE;

foreach version (vers)
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  path = get_kb_item('SMB/Acroread/'+version+'/Path');
  if (isnull(path)) path = 'n/a';

  verui = get_kb_item('SMB/Acroread/'+version+'/Version_UI');
  if (isnull(verui)) verui = version;

  if (
    # 9.x <= 9.5.3
    (ver[0] == 9 && ver[1] < 5) ||
    (ver[0] == 9 && ver[1] == 5 && ver[2] <= 3) ||

    # 10.x <= 10.1.5
    (ver[0] == 10 && ver[1] < 1) ||
    (ver[0] == 10 && ver[1] == 1 && ver[2] <= 5) ||

    # 11.x < 11.0.1
    (ver[0] == 11 && ver[1] == 0 && ver[2] < 1)
  )
  {
    vuln++;
    info += '\n  Path              : '+path+
            '\n  Installed version : '+verui+
            '\n  Fixed version     : 11.0.1 with protected view workaround\n';
  }
  else
    info2 += " and " + verui;

  # check for mitigation
  if (ver[0] == 11 && ver[1] == 0 && ver[2] == 1)
  {
    # check for global, non-overrideable mitigation
    hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
    key = "SOFTWARE\Policies\Adobe\Acrobat Reader\11.0\FeatureLockDown\iProtectedView";
    ipv = get_registry_value(handle:hklm, item:key);
    RegCloseKey(handle:hklm);

    if (!isnull(ipv) && ipv == 0)
    {
      vuln++;
      info += '\n  Path                   : '+path+
              '\n  Installed version      : '+verui+
              '\n  Fixed version          : 11.0.1 with protected view workaround' +
              '\n  Note : Global feature lock down disables protected view.\n';
    }

    if (!isnull(ipv) && ipv > 0)
    {
      mitigation = TRUE;
    }
    else
    {
      # check mitigation per user
      hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:TRUE);
      subkeys = get_registry_subkeys(handle:hku, key:'');
      foreach key (subkeys)
      {
        # verify adobe is installed and available for user
        key_part = '\\SOFTWARE\\Adobe\\Acrobat Reader\\11.0\\InstallPath\\';
        install_path = get_registry_value(handle:hku, item:key + key_part);

        if (!isnull(install_path))
        {
          key_part = "\SOFTWARE\Adobe\Acrobat Reader\11.0\TrustManager\iProtectedView";
          ipv = get_registry_value(handle:hku, item:key + key_part);
          if (isnull(ipv) || ipv == 0)
          {
            vuln++;
            info += '\n  Path                   : '+path+
                    '\n  Installed version      : '+verui+
                    '\n  SID without workaround : '+ key +
                    '\n  Fixed version          : 11.0.1 with protected view workaround\n';
          }
          else
            mitigation = TRUE;
        }
      }
      RegCloseKey(handle:hku);
    }
  }
}

close_registry();

if (info)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    if (vuln > 1) s = "s of Adobe Reader are";
    else s = " of Adobe Reader is";

    report =
      '\nThe following vulnerable instance'+s+' installed on the'+
      '\nremote host :\n'+
      info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}

if (mitigation)
  exit(0, "The host is not affected since the workaround has been applied.");

if (info2)
{
  info2 -= " and ";
  if (" and " >< info2) be = "are";
  else be = "is";

  exit(0, "The host is not affected since Adobe Reader "+info2+" "+be+" installed.");
}
else exit(1, "Unexpected error - 'info2' is empty.");
