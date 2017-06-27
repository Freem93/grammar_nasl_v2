#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40618);
  script_version("$Revision: 1.11 $");

  script_bugtraq_id(35256);
  script_osvdb_id(55060);

  script_name(english:"SAP SAPgui SAPIrRfc ActiveX (sapirrfc.dll) Accept Function Overflow");
  script_summary(english:"Checks version of affected ActiveX control");

  script_set_attribute( attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability."  );
  script_set_attribute( attribute:"description",  value:
"The remote host contains the 'SAPIrRfc' ActiveX control included with
SAP GUI version 6.40 for Windows.

This control is reportedly affected by a heap-based overflow involving
the 'Accept' method of 'IRfcServer' interface of the 'SAPIrRfc'
control.

If an attacker can trick a user on the affected host into visiting a
specially crafted web page, this issue could be leveraged to execute
arbitrary code on the host subject to the user's privileges.

The existence of this vulnerability is confirmed in sapirrfc.dll
version 4.0.2.4.  Previous versions may also be affected."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dsecrg.com/pages/vul/show.php?id=115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/504141/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://service.sap.com/sap/support/notes/1286637"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Apply the patch for the control as described in the vendor advisory. "
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/06/08"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2008/11/13"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/08/17"
  );
 script_cvs_date("$Date: 2014/06/05 04:45:41 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:sap:sap_gui");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) audit(AUDIT_KB_MISSING, 'SMB/Registry/Enumerated');
if (activex_init() != ACX_OK) audit(AUDIT_FN_FAIL, "activex_init");

# Locate the file used by the controls.
clsid = "{77F12F8A-F117-11D0-8CF1-00A0C91D9D87}";

file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  exit(1, 'activex_get_filename() returned NULL.');
}

if (!file)
{
  activex_end();
  audit(AUDIT_ACTIVEX_NOT_FOUND, clsid);
}
  
version = activex_get_fileversion(clsid:clsid);
if (!version || isnull(version))
{
  activex_end();
  audit(AUDIT_VER_FAIL, file);
}

activex_end();

report = "";

if (report_paranoia > 1)
{
  report = string(
    "\n",
    "  Class Identifier : ", clsid, "\n",
    "  Filename         : ", file, "\n",
    "  Version          : ", version, "\n",
    "\n",
    "Note, though, that Nessus did not check whether the kill bit was \n",
    "set for the control's CLSID because the Report Paranoia setting \n",
    "was in effect when this scan was run.\n"
  );
}
else if(activex_get_killbit(clsid:clsid) == 0)
{
  report = string(
    "\n",
    "  Class Identifier : ", clsid, "\n",
    "  Filename         : ", file, "\n",
    "  Version          : ", version, "\n",
    "\n",
    "Moreover, its kill bit is not set so it is accessible via Internet\n",
    "Explorer.\n"
  );
}

if (report != "")
{
  if (report_verbosity > 0)
    security_hole(port:kb_smb_transport(), extra:report);
  else
    security_hole(kb_smb_transport());
  exit(0);
}
else audit(AUDIT_ACTIVEX, version);
