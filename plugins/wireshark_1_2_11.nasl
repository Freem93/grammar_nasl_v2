#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(48943);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/03/21 16:56:11 $");

  script_cve_id("CVE-2010-3133");
  script_bugtraq_id(42630);
  script_osvdb_id(67504);
  script_xref(name:"EDB-ID", value:"14721");

  script_name(english:"Wireshark / Ethereal < 1.2.11 / 1.0.16 Path Subversion Arbitrary DLL Injection Code Execution");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis",value:
"The remote Windows host contains an application that allows arbitrary
code execution."
  );
  script_set_attribute(attribute:"description",value:
"The installed version of Wireshark or Ethereal is 1.2.0 - 1.2.10 or
0.8.4 - 1.0.15.  Such versions are affected by the following
vulnerability :

  - The application uses a fixed path to look for specific
    files or libraries, such as for 'airpcap.dll', and this
    path includes directories that may not be trusted or
    under user control. If a malicious DLL with the same
    name as a required DLL is located in the application's
    current working directory, the malicious DLL will be
    loaded. (Bug 5133)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://msdn.microsoft.com/en-us/library/ff919712(VS.85).aspx"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.acrossecurity.com/aspr/ASPR-2010-08-18-1-PUB.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://blog.rapid7.com/?p=5325"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5133"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.wireshark.org/security/wnpa-sec-2010-09.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.wireshark.org/security/wnpa-sec-2010-10.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Wireshark version 1.2.11 / 1.0.16 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/31");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wireshark:wireshark");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");

  script_dependencies("wireshark_installed.nasl");
  script_require_keys("SMB/Wireshark/Installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

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

  if (
    # 0.8.4 up to and including 1.0.15 (wnpa-sec-2010-09)
    (ver[0] == 0 && ((ver[1] == 8 && ver[2] >= 4) || ver[1] >= 9 )) ||
    (ver[0] == 1 && ver[1] == 0 && ver[2] < 16) ||
    # 1.2.0 up to and including 1.2.10 (wnpa-sec-2010-10)
    (ver[0] == 1 && ver[1] == 2 && ver[2] < 11)
  )
    info +=
      '\n  Path              : ' + installs[install] +
      '\n  Installed version : ' + version  +
      '\n  Fixed version     : 1.2.11 / 1.0.16\n';
  else
    info2 += 'Version '+ version + ', under '+ installs[install] + '. ';
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
  exit(0);
}
if (info2)
  exit(0, "The following instance(s) of Wireshark / Ethereal are installed and are not vulnerable : "+info2);
