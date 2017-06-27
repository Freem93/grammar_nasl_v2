#TRUSTED 5e126f54ff082e87fbcc5be3dda25224931369d84dd4f70610235ad8ae172de75f1be4c132e2b28716a569eb8fb94c689449cf00ea8566252683d8647ff06a327c2c5c31b1fd9a7a85602d2de891f6a3b7573fe6773ea8edda985778f480a020dd5f4c60a661d20896683481728bec8cd701fab643c600a94e0477fe3980e19d0409e74d99bcf9704ba35c7ec894c7c9e1587cee7441a856798ea23bb7a855cc1bddf03c046b36e23fa654476899eb68373a0a54ece5e6ed1d82a2126e9df9eb0b9076de5cf6b466f7952b509b10b08b0d90a19eb1c67771dfca76acaaba9b182deb59e4dfcea34291f206ee2b36db2f0a3b0b696d9be195b3736ed31ec80527299830941142066136805cdc4140731f6f776f4b9a2d885e4607106e5619e9931dc6567130b9a8280a9c2329473c57df47f4d36d472f46af519959b2ad3853cbdd967355c69f8ee124615e411f5496148246a85d417f4f088a85ab182a78d1f33e5458a73f88e3e2d138903d2c281a713017e6063cf7e45b8db4ee822e3924697eeb49caade4d482057ce46f6075d388ebcfa3b20aea5d173588b69a08c8990e16c241b9da085935464220cf4b69daaa41973394c02e5a280b4416f07955b4e0bca53e23867824980891139b033bb82af578bbcbc0863d33addc462be4b0c74c5a484d22aa1c71e5ec005696334d3fdcfce1d47510d06fa00f076358175f60e5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73414);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/15");

  script_cve_id("CVE-2014-1761");
  script_bugtraq_id(66385);
  script_osvdb_id(104895);
  script_xref(name:"MSFT", value:"MS14-017");
  script_xref(name:"IAVA", value:"2014-A-0049");

  script_name(english:"MS14-017: Vulnerabilities in Microsoft Word and Office Web Apps Could Allow Remote Code Execution (2949660) (Mac OS X)");
  script_summary(english:"Checks version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Word that
is affected by one or more unspecified memory corruption
vulnerabilities.

By tricking a user into opening a specially crafted file, it may be
possible for a remote attacker to take complete control of the system
or execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms14-017");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS14-017 Microsoft Word RTF Object Confusion');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");


# Gather version info.
info = '';
installs = make_array();

prod = 'Office for Mac 2011';
plist = "/Applications/Microsoft Office 2011/Office/MicrosoftComponentPlugin.framework/Versions/14/Resources/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^14\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '14.4.1';
  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(fix); i++)
    if ((ver[i] < fix[i]))
    {
      info +=
        '\n  Product           : ' + prod +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
      break;
    }
    else if (ver[i] > fix[i])
      break;
}


# Report findings.
if (info)
{
  if (report_verbosity > 0) security_hole(port:0, extra:info);
  else security_hole(0);

  exit(0);
}
else
{
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac 2011 is not installed.");
  else
  {
    msg = 'The host has ';
    foreach prod (sort(keys(installs)))
      msg += prod + ' ' + installs[prod] + ' and ';
    msg = substr(msg, 0, strlen(msg)-1-strlen(' and '));

    msg += ' installed and thus is not affected.';

    exit(0, msg);
  }
}
