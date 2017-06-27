#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55653);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/05/23 15:38:26 $");

  script_cve_id("CVE-2011-2882", "CVE-2011-2883");
  script_bugtraq_id(48676);
  script_osvdb_id(74191, 74192);
  script_xref(name:"EDB-ID", value:"17762");

  script_name(english:"Citrix Access Gateway Plug-in for Windows ActiveX Control Multiple Vulnerabilities (CTX129902)");
  script_summary(english:"Checks control's version / kill bit");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an ActiveX control that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Citrix Access Gateway ActiveX control for Citrix Access Gateway
Enterprise Edition is installed on the remote Windows host.  It is the
ActiveX component of the Citrix Access Gateway Plug-in for Windows and
provides an SSL-based VPN via a web browser.

The installed version of this control is affected by the following
vulnerabilities that could lead to arbitrary code execution :

  - The control loads a dynamic link library (DLL) when
    processing HTTP header data from the Access Gateway
    server without properly ensuring that the DLL has a
    valid signature. (ZDI 928)

  - The control copies HTTP header data from the Access
    Gateway server into a fixed-size stack buffer without
    verifying the size of the data, which could result in
    a buffer overflow. (ZDI 929)"
  );
   # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=928
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9953dfa4");
   # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=929
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0fe00ad");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518891/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX129902");
  script_set_attribute(
    attribute:"solution",
    value:
"Either set the kill bit for the control or upgrade to Citrix Access
Gateway Enterprise Edition 8.1-67.7 / 9.0-70.5 / 9.1-96.4 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Citrix Gateway ActiveX Control Stack Based Buffer Overflow Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:access_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


get_kb_item_or_exit("SMB/Registry/Enumerated");
if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");


# Determine if the control is installed.
clsid = '{181BCAB2-C89B-4E4B-9E6B-59FA67A426B5}';

file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  exit(1, "activex_get_filename() returned NULL.");
}
if (!file)
{
  activex_end();
  exit(0, "The control is not installed since the class id '"+clsid+"' is not defined on the remote host.");
}


# Get its version.
version = activex_get_fileversion(clsid:clsid);
if (!version)
{
  activex_end();
  exit(1, "Failed to get file version of '"+file+"'.");
}
ver_pat = "^([0-9]+\.[0-9]+)\.([0-9]+\.[0-9]+)$";
version_ui = ereg_replace(pattern:ver_pat, replace:"\1-\2", string:version);


# And check it.
if (version =~ "^8\.1\.") fixed_version = "8.1.67.7";
else if (version =~ "^9\.0\.") fixed_version = "9.0.70.5";
else if (version =~ "^9\.1\.") fixed_version = "9.1.96.4";
else exit(0, "Version "+version_ui+" of the control is installed, but it is not affected.");

info = '';
rc = activex_check_fileversion(clsid:clsid, fix:fixed_version);
if (rc == TRUE)
{
  if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
  {
    fixed_version_ui = ereg_replace(pattern:ver_pat, replace:"\1-\2", string:fixed_version);

    info += '\n  Class Identifier  : ' + clsid +
            '\n  Filename          : ' + file +
            '\n  Installed version : ' + version_ui +
            '\n  Fixed version     : ' + fixed_version_ui + '\n';
  }
}
activex_end();


# Report findings.
if (info)
{
  if (report_paranoia > 1)
  {
    report = info +
      '\n' +
      'Note, though, that Nessus did not check whether the kill bit was\n' +
      "set for the control's CLSID because of the Report Paranoia setting" + '\n' +
      'in effect when this scan was run.\n';
  }
  else
  {
    report = info +
      '\n' +
      'Moreover, its kill bit is not set so it is accessible via Internet\n' +
      'Explorer.\n';
  }

  if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
  else security_hole(kb_smb_transport());

  exit(0);
}
else
{
  if (rc == FALSE) exit(0, "The control is not affected since it is version "+version_ui+".");
  else if (rc == TRUE) exit(0, "Version "+version_ui+" of the control is installed, but its kill bit is set.");
  else exit(1, "activex_check_fileversion() failed.");
}
