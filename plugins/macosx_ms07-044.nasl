#TRUSTED a9e0bbb309a0063f6cc3f42ab73c7f3dd6a7573ddf0f73f42d5739c2c2d48511bb23516ed2445f9f28dc8b8799bf19603f87f7f6b4030c8ec41a55ed5655a50f5f0d9ac36f3acf46ecaca4bd38875ef2b2cf60ed275bf07422ef81c435f87a460702fa02a4e782410cb3c37db6b01b79d259bc0df07912edf3a57a4eb51f846f8ee93edae1fb7d9f647325f99ed662a6df83f4b239b5fc7116e17fdf532b8189a3994bc937afaa71dd1174eac237ec0c11d1547a4742068e6895b541b765c48930baa27e57b81136792309253fb3b0495a1f744a284492bbd5e4821fdef0db0d7c9f3ad75eaa6eb0ada8ce27588bde37cc6547683974ed8808be828f413171338ae96fbdccc09f35e8fa50eec4d401af25bd607faf781453dbd367c380a7a82ccfc84b765aba502046af7d59feeeac154a0deebaf4b4dc9690fa60b66c7dfc6c1cea6af4d8d8c1ce13e80f2c3300b40eda4574782e6fd95129e08e491ce5323088b9682461a8fdaf4ce3defbe3b015c57acb2013865ee3503569d1c62451546d89687a345e9226da19b4880d56a3351b19331625f1423c9c15ff378ab1d3a95386283fd4842fe9c302075edd10d37e59b5c26500700a138ede907c86940e470a90210add224984090735c4e197c533ddd9d3367200c5aa603d1efa80e8f94643586c41918f68b9e6e9690cd92cae04e3a7dfc7ec81047396d83e3c4bc6f69282
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50053);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2007-2224", "CVE-2007-3890");
  script_bugtraq_id(25280, 25282);
  script_osvdb_id(36383, 36387);
  script_xref(name:"MSFT", value:"MS07-043");
  script_xref(name:"MSFT", value:"MS07-044");

  script_name(english:"MS07-043 / MS07-044: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (921503 / 940965) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office 2004
for Mac that is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Office file or viewing a specially crafted web page,
these issues could be leveraged to execute arbitrary code subject to
the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-043");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-044");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office 2004 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119,189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/14");
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

  fixed_version = '11.3.7';
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
