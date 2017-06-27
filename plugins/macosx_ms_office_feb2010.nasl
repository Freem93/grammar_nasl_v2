#TRUSTED 73fd14f6e8dac48cf102b9e4ef378db884740de150470611b6b81d4cd0bbce52161f1af0e30b359a5d6557f56d97a4e276fe24125b197480872739fecef08d39e27f766446a0e0b61c3cf9bcdb6496f8536daeb32efc96e911c63d502fb30841f664a57643479e8d9dd44b11bf3228511ebcb090d3d7b95451a1a5682f88b1e7dc1e28df3d62f9c60cab38b8052a938b6e9f655ff7a61e209e88f97038e293c63565ca248549e2bb7e2580f78b4807032f13fdb3e53e0b3e3ab5ada853c5ee12fb61e76f6a73ac63de93dc996f4a819b57eeda9563cced01b493db67cefba0bf8eccaee26456ebaf2ca3618c91dcb5c967503f535d90f19a005c2a24b90078e33c89877c999e0037ccf2bfb4225b881c91468539d71a70d63c5c0bf1e3aaeb18de693347b859e9063c2a9e0335f98b1cb678ac3288b26ee3b1c6ec37fdd5f90c314d2c5109f0b59670d067a770406ee923083581703cd37f5679053d2ad0fc2a6c3ffaa594345745c05e5a565ab126c560b7b0b70bf204649b0880e804770b1b38c9a95d28b16e5d0e2e274ad5c64e67a18405937c66b07478288a6e32f0e05bd11a58d068d21a488dd75e4cad7753d4a788be42d1cb06f403d8fe771ddf4ff78b61dba33376a5890755987202648abfb0e3e45d9d83bfc42e5b653e6c8c9f7bec4265c173f4e1e113891f516d353e50627381e0c82dea5d363dd0b911509b68
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50064);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2010-0031", "CVE-2010-0243");
  script_bugtraq_id(38073, 38103);
  script_osvdb_id(62235, 62237);
  script_xref(name:"MSFT", value:"MS10-003");
  script_xref(name:"MSFT", value:"MS10-004");

  script_name(english:"MS10-003 / MS10-004: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (978214 / 975416) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Office or PowerPoint file, these issues could be
leveraged to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms10-003");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms10-004");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office 2004 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");

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
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

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

  fixed_version = '11.5.7';
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
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac 2004 is not installed.");
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
