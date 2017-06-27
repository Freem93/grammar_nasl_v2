#TRUSTED 9a5041efd60f0a9976573da44ca79a4fb3e4f538e9b28bb0acad454f19dd59406a54ae491be3bffcf383cc521f9715e419a19dac53f8e0fd8a17b33cf72fa5705b55f6cae0af85ed0fb5227ecaa962bbf5aa4b9274f2c2ce5827be1cd899c6712e43114383b9fd8a0620c1434f46e619b48821872eafad76da8322d792e1c8c2e3cd9f965f751a1588b4d48f1f97497a40c695174c61105511493505babd4e858736ae056044b9f65b92052880f2040d425b64af7f23c67fe05adf12e47658cc7af51992030a2a2abcc3d7110f007ca2124c2bba4745b99a90cf86b9095e248c1edc5387ff0a7776c4e14ddcada91d45384ba4c65921726305bb35f5bf133d2d519644c9adc4c62eacbedd5f33168197f7765b7691a39a27d3c1c3006f7e09ae83f730e22f6399352132916c504cb0929501d85affcab6fb99b6e72df2de11e0450ef0f8c6d63b2f649411907b2f4cffac2430994d14f2fb400a6e40a0ffc16c949f138afdeb341ad5a64344e37c652b42b4cce5506c6250bece7fac1014309aceee50aa94d5f9bd95ba4cb31d1a3752bb66f5487fe0f437aa52d09385ba1bf1fb63fb7857884bda7043da1b70e2ad4c5423e2d623401ebf5f81d64d3bebddb53d8d656dc5259f878c1b72ab57ca478d590f5bc0e7c30dc16fcb5a849c0337c150f67d57be46b74265829cab6cdfad42250acabd13489f83be800d1aa99c985f
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50054);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2007-3899");
  script_bugtraq_id(25906);
  script_osvdb_id(37632);
  script_xref(name:"MSFT", value:"MS07-060");

  script_name(english:"MS07-060: Vulnerability in Microsoft Word Could Allow Remote Code Execution (942695) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office 2004
for Mac that is affected by a memory corruption vulnerability.

If an attacker can trick a user on the affected host into opening a
specially crafted Word file, these issues could be leveraged to
execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-060");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office 2004 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

  fixed_version = '11.3.8';
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
