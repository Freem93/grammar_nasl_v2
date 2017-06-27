#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(28332);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2007-5775");
  script_bugtraq_id(26210);
  script_osvdb_id(40862);

  script_name(english:"BitDefender Online Anti-Virus Scanner ActiveX OScan8.ocx / OScan8.ocx InitX Method Arbitrary Code Execution");
  script_summary(english:"Checks version of BDSCANONLINE ActiveX control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the 'BDSCANONLINE' ActiveX control, used by
the BitDefender Online Scanner, a web-based virus scanner.

The version of this control installed on the remote host fails to
properly validate Unicode values passed to the 'InitX' function as a
domain key.  If a remote attacker can trick a user on the affected
host into visiting a specially crafted web page, these issues could be
leveraged to allocate arbitrary heap-based memory and overwrite memory
within the Internet Explorer or host ActiveX process, which could
result in execution of arbitrary code on the host subject to the
user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://research.eeye.com/html/advisories/published/AD20071120.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/483986/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"The vendor has reportedly released an update that can be obtained
by visiting the URL below, running a scan, and allowing the scanner to
update the antivirus engine :

http://www.bitdefender.com/scan8/ie.html" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/11/27");
 script_cvs_date("$Date: 2015/10/13 15:19:32 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe",value:"cpe:/a:bitdefender:antivirus");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

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

info = "";
clsids = make_list(
  "{4FA3B676-FF36-4967-B283-19AE85D7D4E6}",
  "{5D86DDB5-BDF9-441B-9E9E-D4730F4EE499}"
);
foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (file && file =~ "oscan(8|81)\.ocx")
  {
    if (
      report_paranoia > 1 ||
      activex_get_killbit(clsid:clsid) == 0
    )
    {
      info += '  ' + file + '\n';
      if (!thorough_tests) break;
    }
  }
}
activex_end();


if (info)
{
  report = string(
    "\n",
    "Nessus found the following affected control(s) installed :\n",
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

