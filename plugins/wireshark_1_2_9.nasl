#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46864);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/21 14:22:37 $");

  script_cve_id(
    "CVE-2010-2283",
    "CVE-2010-2284",
    "CVE-2010-2285",
    "CVE-2010-2286",
    "CVE-2010-2287"
  );
  script_bugtraq_id(40728, 42618);
  script_osvdb_id(65371, 65372, 65373, 65374, 65375);
  script_xref(name:"Secunia", value:"40112");

  script_name(english:"Wireshark / Ethereal < 1.0.14 / 1.2.9 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis",value:
"The remote host has an application that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(attribute:"description",value:
"The installed version of Wireshark or Ethereal is potentially
affected by multiple vulnerabilities. 

 - The SMB dissector can be affected by a NULL pointer
   dereference. (Bug 4734)

 - The ANS.1 BER dissector can be affected by a buffer
   overflow.

 - The SMB PIPE dissector can be affected by a NULL pointer
   dereference on some platforms.

 - The SigComp Universal Decompressor Virtual Machine can
   be affected by an infinite loop or a buffer overflow.
   (Bug 4826, 4837)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2010-05.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2010-06.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Wireshark version 1.0.14 / 1.2.9 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/11");
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

info = "";
info2 = "";
foreach install(keys(installs))
{
  if ("/Installed" >< install) continue;

  version = install - "SMB/Wireshark/";
  ver = split(version, sep:".", keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Affects  0.8.20 to 1.0.13 AND 1.2.0 to 1.2.8
  if (
      (
        (ver[0] == 0 && ((ver[1] == 8 && ver[2] >= 20) || ver[1] >= 9 ))
        ||
        (ver[0] == 1 && ver[1] ==0 && ver[2] < 14)
      )
      ||
      (
        ver[0] == 1 && ver[1] == 2 && ver[2] <= 8
      ) 
  )
    info +=
      '\n  Path              : ' + installs[install] +
      '\n  Installed version : ' + version  +
      '\n  Fixed version     : 1.2.9 / 1.0.14\n';
  else
    info2 += '  - Version ' + version + ', under ' + installs[install] +'\n';
}

# Report if any were found to be vulnerable
if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 4) s = "s of Wireshark / Ethereal are";
    else s = " of Wireshark / Ethereal is";

    report = 
      '\n' +
      'The following vulnerable instance' + s + ' installed :\n' +
      '\n' + info;
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
if (info2)
  exit(0, "The following instance(s) of Wireshark / Ethereal are installed and are not vulnerable : "+info2);
