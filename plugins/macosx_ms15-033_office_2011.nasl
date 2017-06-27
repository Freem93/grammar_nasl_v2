#TRUSTED 5b1b21d03fbdde3e89d42b82610b9b1a35210f425dd42bafc15cd612c788ea182121493adb464be0ce636ae6a7b71a3a6418c3f88aa91d8354f722807b5dff55c0bffbf67e7e9bee34794c96600cc55450e4785a19b77bb443b4bb51c66bfd75f026f9eb51360939e741bf6a88066bb24d5df462596485803e979f371fda07cc62739555c0cf177dac057895baeaf694e5121b4a9bd25187dbd7933b27fa78e6b3ba2a8259ef61c287090893aefafa7b48177bb1656a3b150c4343ce4e7a1a27f8445b89631667bedab020dfac51bf3a41d35ec08f50f8d4cd32f57f798499b23c6dc2b1d930e285b04a5c55f0bf386690535d55bf5046a9c7d6c1c90454ba2edaec10f543c45071e38d9ecf0e46204de088314d9cc46df8807da4c0656c1477b873a2334cbb39551dd8303be074b533e84a85107acbea806d02cac771e4dfc2df2a6339b8374e3a60568f9ad38163fdc31487fe695a02677ef9c771df14708d946aeb1c4a4c202996dcbf992e9cd910ea0c78d2c5eeb06a66162a350308410a5e3f08c3ce73ada70cb8afd805886bbeba6143e52638969ab24f4f7da39deab2e5d98e3e0f13e4218b69b2bd3d911dd9de1962ab0da204a1b84476b67a0f652a7f1bd297636f0c0b9042e456de2f17d3910fb36562fde040443cf06edfe958aedc3423f8cd98cb6c7772dfb605e0b06adce7a61d980d54b51d35afb8f59146b6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82767);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/15");

  script_cve_id("CVE-2015-1639", "CVE-2015-1641");
  script_bugtraq_id(73991, 73995);
  script_osvdb_id(120624, 120628);
  script_xref(name:"MSFT", value:"MS15-033");
  script_xref(name:"IAVA", value:"2015-A-0090");

  script_name(english:"MS15-033: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (3048019)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Word installed
that is affected by multiple vulnerabilities :

  - A cross-site scripting vulnerability exists due to
    improper sanitization of HTML strings. A remote attacker
    can exploit this issue by convincing a user to open a
    file or visit a website containing specially crafted
    content, resulting in execution of arbitrary code in the
    context of the current user. (CVE-2015-1639)

  - A remote code execution vulnerability exists due to
    improper handling rich text format files in memory. A
    remote attacker can exploit this vulnerability by
    convincing a user to open a specially crafted file using
    the affected software, resulting in execution of
    arbitrary code in the context of the current user.
    (CVE-2015-1641)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-033");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_for_mac:2011");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:outlook_for_mac_for_office_365");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

  fixed_version = '14.4.9';
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
  set_kb_item(name:"www/0/XSS", value:TRUE);
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
