#TRUSTED ab35c19fd26739b0749195cdfc75bf3248c30b2a03ffe5ad3645ab86d7312045128778b7eb63567eb3ab25cbe6e1e7f861b6a229102ac9e0948a322ddd9c1368ac437c88c9688c7a1e8ed90a2a4c767a2d17abf4fc797dc42ac69537052d49ef1f5e4408f58061f0cc27e41c913d89cfed4faa9e1a61dabe16a7cc26db85beb7b09a33794fb981eea9fe909c84b237a80ab0709b370a3273d15f754eef7ee8b8f9f2edf6f34040f57b2e87a79dab2de105b0b64ae5753a14da614f29cb7a5534f7b1b5554d4c46f0222934906461b532b0af7be2cea72469f2dedb15f33599f7ea835fb7cde1bec9910c1f48904d8c2dd2605664a641e9b9fbc87639671643fc9df8e0420aaf2c5cf484faafc2446dcb6cac36d443a0bb9cfaef8056a0b6b29955e8472ba747b1966e550e3a4c8bb8f98d7ce8aa3ebbb5d178ed01b17e4545cae9dac87e324b9948ad483fb108624a5a3f306061beb71e8a223a7d4b7a229bf3c285bf37c1c26f1b6733792016cc80fc48a979790fcde3f67ce6e8ff1f82564d64f57871607dc1312a09c711268d4d5b92b2bc051724e4bc283f2eb49c802bdcb30001503e4907a62c55aecf310246fd3f6b1fe8205192192bc991a069e0a2f603b7bf1398789c2502fa2e0d70af76c40aee919b1550891636152e154f7d588579e5599bf6c92604d502feed5673af3afaa8527214f9d2c13ad2c64f069af38f
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50055);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2007-0065", "CVE-2008-0103");
  script_bugtraq_id(27661, 27738);
  script_osvdb_id(41462, 41463);
  script_xref(name:"MSFT", value:"MS08-008");
  script_xref(name:"IAVA", value:"2008-A-0006");
  script_xref(name:"MSFT", value:"MS08-013");

  script_name(english:"MS08-008 / MS08-013: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (947890 / 947108) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office 2004
for Mac that is affected by multiple vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Office file or viewing a specially crafted web page,
these issues could be leverage to execute arbitrary code subject to
the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-008");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-013");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office 2004 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");


function exec(cmd)
{
  local_var buf, ret;

  if (islocalhost())
    buf = pread(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(1, "ssh_open_connection() failed.");
    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");
if (!egrep(pattern:"Darwin.*", string:uname)) exit(1, "The host does not appear to be using the Darwin sub-system.");


# Gather version info.
info = '';
installs = make_array();

prod = 'Office 2004 for Mac';
cmd = GetCarbonVersionCmd(file:"Microsoft Component Plugin", path:"/Applications/Microsoft Office 2004/Office");
version = exec(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^11\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '11.4.0';
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
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet') security_hole(port:0, extra:info);
  else security_hole(0);

  exit(0);
}
else
{
  if (max_index(keys(installs)) == 0) exit(0, "Office 2004 for Mac is not installed.");
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
