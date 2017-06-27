#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(26061);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2007-0322", "CVE-2007-4471");
  script_bugtraq_id(25544);
  script_osvdb_id(37134, 37243);
  script_xref(name:"CERT", value:"907481");
  script_xref(name:"CERT", value:"979638");

  script_name(english:"Intuit QuickBooks Online Edition < 10 ActiveX Multiple Vulnerabilities");
  script_summary(english:"Checks for QuickBooks Online Edition control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
various vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host contains an Active control associated with QuickBooks
Online Edition, a variant of Intuit QuickBooks implemented as an
ActiveX control.

The version of this control on the remote host reportedly is affected
by multiple and as-yet unspecified stack-based buffer overflows that
could allow for the execution of arbitrary code.  It also fails to
properly restrict access to methods, which could be abused to download
or upload files arbitrary files.

Successful exploition requires that an attacker trick a user on the
affected host into visiting a specially crafted web page, and code
execution and file access would be subject to the user's privileges." );
 script_set_attribute(attribute:"solution", value:
"Disable the use of this ActiveX control from within Internet Explorer
by setting its kill bit.  Note that upgrading to version 10 or later
of the QuickBooks Online Edition does not necessarily remove earlier
versions of the control." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(22, 119, 264);


 script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/09/04");
 script_cvs_date("$Date: 2016/11/23 20:42:24 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Locate files used by the control.
if (activex_init() != ACX_OK) exit(0);

info = "";
clsids = make_list(
  # nb: each version of QuickBooks Online Edition uses a different CLSID.
  "{CF9DEB90-8DE3-11D5-BAE4-00105AAAFF94}",
  "{4F720B9C-24B1-4948-A035-8853DC01F19E}",
  "{2EFF8C97-F2A8-4395-9F47-9A06F998BF88}",
  "{2CC3D8DE-18BF-43ff-8CB8-21B442300FD5}",
  "{DBB177CC-6908-4b53-9BEE-F1C697818D65}",
  "{A80D199B-CFDD-4da4-8C47-2310D5B8DD97}",
  "{0D3983A9-4E29-4f33-8313-DA22B29D3F87}",
  "{D92D7607-05D9-4dd8-B68B-D458948FB883}",
  "{8CE3BAE6-AB66-40b6-9019-41E5282FF1E2}",
  "{40F8967E-34A6-474a-837A-CEC1E7DAC54C}"
);
foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (file)
  {
    if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
    {
      info += '  ' + clsid + '\n' + 
              '    ' + file + '\n';
      if (!thorough_tests) break;
    }
  }
}
activex_end();


if (info)
{
  report = string(
    "Nessus found the control installed as :\n",
    "\n",
    info
  );

  if (!thorough_tests)
  {
    report = string(
      report,
      "\n",
      "Note that Nessus did not check whether there were other instances\n",
      "installed because the 'Perform thorough tests' setting was not enabled\n",
      "when this scan was run.\n"
    );
  }

  if (report_paranoia > 1)
    report = string(
      report,
      "\n",
      "Note that Nessus did not check whether the kill bit was set for\n",
      "the control(s) because of the Report Paranoia setting in effect\n",
      "when this scan was run.\n"
    );
  else 
    report = string(
      report,
      "\n",
      "Moreover, the kill bit was  not set for the control(s) so they\n",
      "are accessible via Internet Explorer.\n"
    );
  security_hole(port:kb_smb_transport(), extra:report);
}
