#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33095);
  script_version("$Revision: 1.16 $");

  script_cve_id(
    "CVE-2007-5604",
    "CVE-2007-5605",
    "CVE-2007-5606",
    "CVE-2007-5607",
    "CVE-2007-5608",
    "CVE-2007-5610",
    "CVE-2008-0952",
    "CVE-2008-0953"
  );
  script_bugtraq_id(
    29529, 
    29530, 
    29531, 
    29532, 
    29533, 
    29534, 
    29535, 
    29536
  );
  script_osvdb_id(
    46231, 
    46232, 
    46233, 
    46234, 
    46236, 
    46237, 
    46238, 
    46239
  );
  script_xref(name:"Secunia", value:"30516");

  script_name(english:"HP Instant Support HPISDataManager.dll ActiveX Control < 1.0.0.24 Vulnerabilities");
  script_summary(english:"Checks version of HPISDataManager.dll control");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has several ActiveX controls that are affected
by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host contains several ActiveX controls in HP Instant
Support HPISDataManager.dll, a web-based diagnostic tool from
Hewlett-Packard. 

The version of the controls installed on the remote host reportedly
are affected by several issues.  If an attacker can trick a user on
the affected host into viewing a specially crafted HTML document, 
this method could be used to execute arbitrary code by means of
buffer overflows or to execute delete, download, and write to
arbitrary files on the affected system, all subject to the user's
privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.csis.dk/dk/forside/CSIS-RI-0003.pdf" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Jun/29" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Jun/26" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to HP Instant Support version 1.0.0.24 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(94);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/05");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/06/03");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:instant_support");
 script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsid = "{14C1B87C-3342-445F-9B5E-365FF330A3AC}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  ver = activex_get_fileversion(clsid:clsid);
  if (ver && activex_check_fileversion(clsid:clsid, fix:"6.0.10.50") == TRUE)
  {
    report = NULL;
    if (report_paranoia > 1)
      report = string(
        "\n",
        "Version ", ver, " of the vulnerable control is installed as :\n",
        "\n",
        "  ", file, "\n",
        "\n",
        "Note, though, that Nessus did not check whether the kill bit was\n",
        "set for the control's CLSID because of the Report Paranoia setting\n",
        "in effect when this scan was run.\n"
      );
    else if (activex_get_killbit(clsid:clsid) == 0)
      report = string(
        "\n",
        "Version ", ver, " of the vulnerable control is installed as :\n",
        "\n",
        "  ", file, "\n",
        "\n",
        "Moreover, its kill bit is not set so it is accessible via Internet\n",
        "Explorer.\n"
      );
    if (report)
    {
      if (report_verbosity) security_hole(port:kb_smb_transport(), extra:report);
      else security_hole(kb_smb_transport());
    }
  }
}
activex_end();
