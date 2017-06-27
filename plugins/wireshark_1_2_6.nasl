#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44338);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2010-0304");
  script_bugtraq_id(37985);
  script_osvdb_id(61987);

  script_name(english:"Wireshark / Ethereal Dissector LWRES Multiple Buffer Overflows");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis",value:
"The remote host has an application that is affected by several buffer
overflows."
  );
  script_set_attribute(attribute:"description",value:
"The installed version of Wireshark or Ethereal is potentially
vulnerable to attack by handling data associated with the LWRES
dissector. 

These vulnerabilities can result in a denial of service, or possibly
arbitrary code execution.  A remote attacker can exploit these issues
by tricking a user into opening a maliciously crafted capture file. 
Additionally, if Wireshark is running in promiscuous mode, one of
these issues can be exploited remotely."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.wireshark.org/security/wnpa-sec-2010-02.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Wireshark version 1.0.11 / 1.2.6 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Wireshark LWRES Dissector getaddrsbyname_request Buffer Overflow (loop)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
  script_cwe_id(119);
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2010/01/27"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/01/27"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2010/01/29"
  );
 script_cvs_date("$Date: 2016/11/29 20:13:38 $");
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

  # Affects 0.9.15 - 1.0.10 and 1.2.0 - 1.2.5
  if (
    (ver[0] == 0 && ver[1] == 9 && ver[2] > 14)
    ||
    (
      ver[0] == 1 &&
      (
        (ver[1] == 0 && ver[2] < 11) ||
        (ver[1] == 2 && ver[2] < 6)
      )
    )
  ) 
    info +=
      '\n  Path              : ' + installs[install] +
      '\n  Installed version : ' + version  +
      '\n  Fixed version     : 1.0.11 / 1.2.6\n';
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

    report = string(
      "\n",
      "The following vulnerable instance", s, " installed :\n",
      "\n",
      info
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "The host is not affected because Wireshark / Etherealversion "+version+" is installed.");
if (info2)
  exit(0, "The following instance(s) of Wireshark / Ethereal are installed and are not vulnerable : "+info2);
