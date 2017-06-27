#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27854);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/10/07 13:30:46 $");

  script_cve_id("CVE-2007-5755", "CVE-2007-6250");
  script_bugtraq_id(26396, 27207);
  script_osvdb_id(38705, 40199);
  script_xref(name:"CERT", value:"568681");

  script_name(english:"AOL Radio AmpX ActiveX Control Buffer Overflow Vulnerabilities");
  script_summary(english:"Checks version of AmpX ActiveX control");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host contains the 'AmpX' ActiveX control, which is
associated with AOL Radio.

The version of this control installed on the remote host fails to
validate input to several methods before copying it into a finite-
sized buffer using 'strcpy()'.

In addition, it allows remote access to the application
'AOLMediaPlaybackControl', which contains a stack-based buffer
overflow.

If a remote attacker can trick a user on the affected host into visiting
a specially crafted web page, these issues could be leveraged to
overflow a buffer, either in the control itself or in
AOLMediaPlaybackControl.exe, and execute arbitrary code on the host
subject to the user's privileges.");
  # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=623
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b098a46c");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Nov/234");
  script_set_attribute(attribute:"see_also", value:"http://radaol-prod-web-rr.streamops.aol.com/mediaplugin/unagi_patch.exe");
  script_set_attribute(attribute:"solution", value:
"Apply the AOL AmpX Security Update (unagi_patch.exe) referenced above
to upgrade the affected control to version 2.6.2.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:aol:radio");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:aol:aolmediaplaybackcontrol");
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
  "{B49C4597-8721-4789-9250-315DFBD9F525}",
  "{FA3662C3-B8E8-11D6-A667-0010B556D978}"
);

foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (file)
  {
    # Check its version.
    ver = activex_get_fileversion(clsid:clsid);
    if (ver && activex_check_fileversion(clsid:clsid, fix:"2.6.2.6") == TRUE)
    {
      if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
      {
        info += '  - ' + clsid + '\n' + 
                '    ' + file + ', ' + ver + '\n';

        if (!thorough_tests) break;
      }
    }
  }
}
activex_end();


if (info)
{
  info = string(
    "Nessus found vulnerable control(s) installed as :\n",
    "\n",
    info
  );

  if (!thorough_tests)
  {
    info = string(
      info,
      "\n",
      "Note that Nessus did not check whether there were other instances\n",
      "installed because the 'Perform thorough tests' setting was not enabled\n",
      "when this scan was run.\n"
    );
  }

  if (report_paranoia > 1)
    info = string(
      info,
      "\n",
      "Note that Nessus did not check whether the kill bit was set for\n",
      "the control(s) because of the Report Paranoia setting in effect\n",
      "when this scan was run.\n"
    );
  else 
    info = string(
      info,
      "\n",
      "Moreover, the kill bit was not set for the control(s) so they\n",
      "are accessible via Internet Explorer.\n"
    );
  security_hole(port:kb_smb_transport(), extra:info);
}
