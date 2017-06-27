#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27522);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/09 20:54:57 $");

  script_cve_id("CVE-2007-5601");
  script_bugtraq_id(26130);
  script_osvdb_id(41430);
  script_xref(name:"CERT", value:"871673");

  script_name(english:"RealPlayer ActiveX (ierpplug.dll) Playlist Handling Buffer Overflow");
  script_summary(english:"Checks version of MPAMedia.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of RealPlayer installed on the remote Windows host
contains signedness error in its 'MPAMedia.dll' library that can be
exploited via an ActiveX control when handling playlist names to cause
a stack-based buffer overflow. A remote attacker may be able to
exploit this issue to execute arbitrary code subject to the user's
privileges on the affected host.");
  script_set_attribute(attribute:"see_also", value:"http://service.real.com/realplayer/security/191007_player/en/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to RealPlayer 10.5 / 11 beta and apply the patch referenced in
the vendor advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'RealPlayer ierpplug.dll ActiveX Control Playlist Name Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:realnetworks:realplayer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("realplayer_detect.nasl", "smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/RealPlayer/Product", "SMB/RealPlayer/Path", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");


path = get_kb_item_or_exit("SMB/RealPlayer/Path");
prod = get_kb_item_or_exit("SMB/RealPlayer/Product");
if (prod != "RealPlayer") exit(0, "RealPlayer not installed.");


# Unless we're paranoid, make sure the kill bit is not set for the affected control.
clsid = "{FDC7A535-4070-4B92-A0EA-D9994BCC0DC5}";
if (report_paranoia < 2)
{
  killbit = FALSE;

  if (activex_init() != ACX_OK) exit(0);

  file = activex_get_filename(clsid:clsid);
  if (file) killbit = activex_get_killbit(clsid:clsid);
  activex_end();

  if (TRUE == killbit) exit(0);
}


# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");


# Check whether the affected DLL exists.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\plugins\MPAMedia.dll", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
if (!isnull(ver))
{
  fix = split("1.0.4.2840", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
      report = string(
        "\n",
        "Version ", version, " of the affected DLL is installed on the remote host :\n",
        "\n",
        "  ", path, "\\plugins\\MPAMedia.dll\n"
      );
      if (report_paranoia < 2)
        report = string(
          report,
          "\n",
          "Moreover, the kill bit for the CLSID\n",
          clsid, " is not set so this vulnerability\n",
          "can be exploited remotely via Internet Explorer.\n"
        );
      else
        report = string(
          report,
          "\n",
          "Note, though, that Nessus did not check whether the kill bit was set\n",
          "for the CLSID associated with this vulnerability\n",
          "(", clsid, ") because of the Report Paranoia\n",
          "setting in effect when this scan was run.\n"
        );

      security_hole(port:port, extra:report);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
