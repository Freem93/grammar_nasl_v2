#TRUSTED 79e45c9966167d7cd8258db754e1d551332b154576db5ad32be4957e067c4ec28269a1ab93ec4d17672ff83b597b01eab9f4de1c045fcb3306fa2afcff2222f40cc1fc235c04a8c527c954ed96f3b6f3f379ec35f11007f9312f5aa87bb7df36a9eb1499db1e11040085dc93e4c02297250ed0bc0dafc1c6ff3fb3bf76b4eade346462d107232200792d08171f6aa8a6daabf195a80a32bfe42fb028eac0075250e69195cd897bb4cf70d94d45072f0e6c3c32b0a0362b96883f66b546136a7bd5bce2452abec95edb9d354fa71d512112204d99101b8d460523e752fbb38437c219d5e89199f9bcaae38457d96478e6b0c60823ee26aaa34faa85248d211c420429d456ef1baeb48e9690171e6f78afd0aefb882b600c5c2c8eb1f3507a5ba34d2d7631816133802a0103f1575c2861858106de27752ccf7151143f80a8ac72ff4de21ae87eeec4905d6c7892183938c34f10d8c096fe9f0386c04c803bb1a557a1f840512d9956c20442a0021e211e7787441b01bd7d0c37c92c3e079912e3bfc18d37f843116c5576ccc301964ffdba0a1a3062bd100f483780f273041530fe7c9cf05a553e645d2e4909a21955478ecdc12491ba0b0a02b9379bd709cdd45861c9b9ed63a1245291b05654fc528d754cd284feff88365ddc31c5232e0b819037e267bedae6b22393e0bdc3559fa3191e917cbc43b32aed8d7891b35f8f61
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78436);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/15");

  script_cve_id("CVE-2014-4117");
  script_bugtraq_id(70360);
  script_osvdb_id(113190);
  script_xref(name:"MSFT", value:"MS14-061");

  script_name(english:"MS14-061: Vulnerability in Microsoft Word and Office Web Apps Could Allow Remote Code Execution (3000434)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Word that
is affected by a remote code execution vulnerability due to a flaw in
parsing Word documents. This vulnerability can be triggered by
tricking a user into opening a specially crafted Word document.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-061");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
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

  fixed_version = '14.4.5';
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
