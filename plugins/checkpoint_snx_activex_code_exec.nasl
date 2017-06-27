#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55994);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/03 20:48:27 $");

  script_cve_id("CVE-2011-1827");
  script_bugtraq_id(47695);
  script_osvdb_id(74807);

  script_name(english:"Check Point SSL Network Extender ActiveX Control Remote Code Execution");
  script_summary(english:"Checks for the control");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an ActiveX control that is affected by a
remote code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the Check Point SSL Network Extender ActiveX control
installed on the remote Windows host reportedly contains a remote code
execution vulnerability. If an attacker can trick a user on the
affected host into viewing a specially crafted HTML document, he can
leverage this issue to execute arbitrary code on the affected system
subject to the user's privileges."
  );

  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb99505f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?159fd312"
  );

  script_set_attribute(
    attribute:"solution",
    value:"Follow the instructions in Check Point's advisory."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:checkpoint:connectra_ngx");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

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

# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");

clsid = '{B4CB50E4-0309-4906-86EA-10B6641C8392}';

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

ver = activex_get_fileversion(clsid:clsid);

if (ver) ver = string("Version ", ver);
else ver = string("An unknown version");

report = NULL;
if (report_paranoia > 1)
{
  report = string(
    "\n",
    ver, " of the vulnerable control is installed as SlimClient Class with the path :\n",
    "\n",
    "  ", file, "\n",
    "\n",
    "Note, though, that Nessus did not check whether the kill bit was\n",
    "set for the control's CLSID because of the Report Paranoia setting\n",
    "in effect when this scan was run.\n"
  );
}
else if (activex_get_killbit(clsid:clsid) == 0)
{
  report = string(
    "\n",
    ver, " of the vulnerable control is installed as SlimClient Class with the path :\n",
    "\n",
    "  ", file, "\n",
    "\n",
    "Moreover, its kill bit is not set so it is accessible via Internet\n",
    "Explorer.\n"
  );
}

if (report)
{
  if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
  else security_hole(kb_smb_transport());
}
