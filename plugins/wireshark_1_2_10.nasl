#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48213);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_cve_id("CVE-2010-2992", "CVE-2010-2993", "CVE-2010-2994", "CVE-2010-2995");
  script_bugtraq_id(42618);
  script_osvdb_id(65372, 66792, 66793, 67191);
  script_xref(name:"Secunia", value:"40783");

  script_name(english:"Wireshark / Ethereal < 1.0.15 / 1.2.10 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis",value:
"The remote host has an application that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(attribute:"description",value:
"The installed version of Wireshark or Ethereal is potentially
affected by multiple vulnerabilities. 

  - The SigComp Universal Decompressor Virtual Machine could
    potentially overflow a buffer. (Bug 4867)

  - The ANS.1 BER dissector could potentially exhaust the 
    stack memory. (Bug 4984)

  - The GSM A RR dissector is affected by denial of service
    issue. (Bug 4897)

  - The IPMI dissector could get stuck in an infinite loop. 
    (Bug 5053)"
  );
  script_set_attribute(attribute:"see_also",value:"http://www.wireshark.org/security/wnpa-sec-2010-08.html");
  script_set_attribute(attribute:"see_also",value:"http://www.wireshark.org/security/wnpa-sec-2010-07.html");
  script_set_attribute(attribute:"solution",value:"Upgrade to Wireshark version 1.0.15 / 1.2.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/02");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

  exit(0);
}

include("global_settings.inc");

# Check each install.
installs = get_kb_list("SMB/Wireshark/*");
if (isnull(installs)) exit(0, "The 'SMB/Wireshark/*' KB items are missing.");

info  = '';
info2 = '';

foreach install(keys(installs))
{
  if ("/Installed" >< install) continue;

  version = install - "SMB/Wireshark/";
  ver = split(version, sep:".", keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Affects  0.10.8 to 1.0.14 AND 1.2.0 to 1.2.9
  if ((ver[0] == 0 && ((ver[1] == 10 && ver[2] >=  8) || (ver[1] >= 11))) ||
      (ver[0] == 1 && ver[1] ==  0 && ver[2] < 15 )  ||
      (ver[0] == 1 && ver[1] ==  2 && ver[2] < 10 ) 
  ) info +=
      '\n  Path              : ' + installs[install] +
      '\n  Installed version : ' + version  +
      '\n  Fixed version     : 1.0.15 / 1.2.10\n';
  else
    info2 += 'Version '+ version + ', under '+ installs[install] + '. ';
}

# Report if any were found to be vulnerable
if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 1) s = "s of Wireshark / Ethereal are";
    else s = " of Wireshark / Ethereal is";

    report = 
      '\n' +
      'The following vulnerable instance' + s + ' installed :\n' +
      '\n' + info;
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
  exit(0);
}
if (info2)
  exit(0, "The following instance(s) of Wireshark / Ethereal are installed and are not vulnerable : "+info2);
