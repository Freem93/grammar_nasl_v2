#TRUSTED 82a85473c40abaf39055588e9c129d9dfb79f645faa0da374cea1f04f7c280ebe8e344c02ed5e9c660ac41ab69dd7b8ae2d76083cdf4fdb1cb7a241e74898a5d666ab756a4773545aeffbe8fac29a6449805f3200911bd62436c1bf92c1faa9a53092f8522bb8b92fa4c9df0fdb7ed501654466d5b9031ef5a8426ecca6932838b7f5586539d051d685465dc4a5033b8df263f853dc924fc12b90604e9b090e8e31bcf02bb478701978f3631e4d9f248c508186d5b883a89b258f03d0961d8df5789af06b8dbb5325748cb1d4b28895fb526f59bf394fb45ff5f8967f6b5410beeecb7ebedb52e0fa154ae1f40a2641f2988ed61a9bfafbce762a3d7d7ef02ba990ba7fb0fedbc9ddd5c6e88e45bc15ed6e59f701ae6d247c95d8535e9ac90c486b96d19aca3c6921a59c08ec705b08bc4ea74708636a94fedd07dded5ebdb0f755a541266dc48456694aec4227e9d3e8a077ec466d7e64008de68ebfe3a949cb1afe329bf9f4bc807fa0a5dc4bcdbbd5a1f474d30bd459b060c43fe384cac0f67e2689ee870616bad2b010a38a5baf554d876d13656339c4dc6451598b226cfcef97f89cc781e046339a3d74cdd8f6ac7c5865dabfe030ea0ddbf84c50e82207db19c06de761cc8cebc58f093cc56a38ff4c19db26b0c99efa95568c5e2a96c147b90bf32113ef8fb134118196187cbb2f27717b264c726ed04fc0088cfb083
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85349);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/15");

  script_cve_id(
    "CVE-2015-2468",
    "CVE-2015-2469",
    "CVE-2015-2470",
    "CVE-2015-2477"
  );
  script_bugtraq_id(
    76206,
    76212,
    76214,
    76219
  );
  script_osvdb_id(
    125982,
    125983,
    125984,
    125986
  );
  script_xref(name:"MSFT", value:"MS15-081");
  script_xref(name:"IAVA", value:"2015-A-0194");

  script_name(english:"MS15-081: Vulnerability in Microsoft Office Could Allow Remote Code Execution (3072620) (Mac OS X)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Office installed
that is affected by multiple remote code execution vulnerabilities :

  - Multiple remote code execution vulnerabilities exist due
    to improper handling of objects in memory. A remote
    attacker can exploit these vulnerabilities by convincing
    a user to open a specially crafted Office file,
    resulting in the execution of arbitrary code in the
    context of the current user. (CVE-2015-2468,
    CVE-2015-2469, CVE-2015-2477)

  - A remote code execution vulnerability exists when Office
    decreases an integer value beyond its intended minimum
    value. A remote attacker can exploit this vulnerability
    by convincing a user to open a specially crafted Office
    file, resulting in the execution of arbitrary code in
    the context of the current user. (CVE-2015-2470)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-081");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011:mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2016:mac");
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

  fixed_version = '14.5.4';
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
