#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40363);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/10/07 13:30:46 $");

  script_cve_id("CVE-2009-2582");
  script_bugtraq_id(35778);
  script_osvdb_id(56247);
  script_xref(name:"Secunia", value:"35951");

  script_name(english:"Akamai Download Manager ActiveX Control < 2.2.4.8 Buffer Overflow");
  script_summary(english:"Checks version of Download Manager ActiveX control"); 
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is prone to a
buffer overflow attack.");

  script_set_attribute(attribute:"description", value:
"The Windows remote host contains the Download Manager ActiveX control
from Akamai, which helps users download content. 

The version of this ActiveX control on the remote host reportedly is
affected by a buffer overflow vulnerability in 'manager.exe' when
handling Redswoosh downloads.  If an attacker can trick an user on the
affected host into visiting a specially crafted web page, he may be
able to execute arbitrary code on the affected system subject to the
user's privileges.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8641fa7c");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2009/Jul/165");

  script_set_attribute(attribute:"solution", value:
"Manually remove all older versions and, if desired, install version
2.2.4.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date",   value:"2009/07/22");
  script_set_attribute(attribute:"patch_publication_date",  value:"2009/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Locate the file used by the control.
if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");

clsids = make_list("{4871A87A-BFDD-4106-8153-FFDE2BAC2967}",
                   "{FFBB3F3B-0A5A-4106-BE53-DFE1E2340CB1}",
                   "{2AF5BD25-90C5-4EEC-88C5-B44DC2905D8B}");

info = NULL;
foreach clsid (clsids)
{
 file = activex_get_filename(clsid:clsid);

 if (file)
 {
   # Check its version.
   ver = activex_get_fileversion(clsid:clsid);

   # Fixed version of DownloadManagerV2.ocx == 2.2.4.8
   if (ver && activex_check_fileversion(clsid:clsid, fix:"2.2.4.8") == TRUE)
    {
      if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
       {
        info += '  - ' + clsid + '\n' +
                '    ' + file + ', ' + ver + '\n';

        # if (!thorough_tests) break;
        # Do not break the loop if we find a vulnerable clsid.
        # According to iDefense advisory older version are not 
        # automatically removed by newer versions.
       } 
    }
  }
}

activex_end();

if (info)
{
  if (report_verbosity > 0)
  {
    if (report_paranoia > 1)
    {
      report = string(
        "\n",
        "Nessus found the following affected control(s) installed :\n",
        "\n",
        info,
        "\n",
        "Note that Nessus did not check whether the kill bit was set for\n",
        "the control(s) because of the Report Paranoia setting in effect\n",
        "when this scan was run.\n"
      );
    }
    else
    {
      report = string(
        "\n",
        "Nessus found the following affected control(s) installed :\n",
        "\n",
        info,
        "\n",
        "Moreover, the kill bit was  not set for the control(s) so they\n",
        "are accessible via Internet Explorer.\n"
      );
    }
    security_hole(port:kb_smb_transport(), extra:report);
  }
  else security_hole(kb_smb_transport());
} 
