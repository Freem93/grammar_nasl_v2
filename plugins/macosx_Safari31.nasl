#TRUSTED 3b6414c5ca653d8b18ac8bfe9d1fcaccf57fcf6adea957c8e7732e97ae1604914b35b5a291d54526d852967f918b6794e7f0c405560ed31dcd4c8e19d9040522333ffb01b411dd48552f8f7537b43004a2f1bed31c39d2f459a5c175a3a24eae79d8b4cb1e46ad52adb5fbc585d98f99b02c58e51d7c3c22a91cfb27854e350f6eb62ecd749c8392eb8b5bb668424d198f5d2c8fb8a708d088ade5117486f3a37fef86a85e0132d9dce66886c952ed413daafc96acd0ae82b2b594ced3eb80bf859ba3c6ca5ba49f268fb30565db7e9ed68802eea8a83d3b2e7b3ce304109632e479712b26a7bcd67118481647531ebe5fdce80f5761b3b353fcaf3cda082a807a05c38d290d8414014969a24c673de44a6c9ef0d0e27eee2ecf1dda1d7cb816dcb6d0cf5b2231f666893c21089ba0aae9197583dc684bf4cec5a60297bdec73091465c76d514637e3e3190b2ec60c0e84cc2c7878589652d4413b44a4d86a5254e4c58af2e56d542ac1cfbcf931d0006a77f2e3187f79b57acaba1a089a45bf7d3321c40a7c2789f6a2fb14a0cbec860329ba8075035dcf1911badfe51a5e061dc13cf3752e3164387335e260b5d8caaa16b3d4d99b3d66ef7e4cb5bcd1dfe17fff99750f0032828ac841acf3633f5db61e20fd89bfc4b8b46025862551d23985672efb42f5577c4133e66932d3b23c44fa935e9187f88c49ef42a65727914f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(31604);
 script_version("1.17");
 script_set_attribute(attribute:"plugin_modification_date", value:"2015/07/03");

 script_cve_id(
  "CVE-2008-1002",
  "CVE-2008-1003",
  "CVE-2008-1004",
  "CVE-2008-1005",
  "CVE-2008-1006",
  "CVE-2008-1007",
  "CVE-2008-1008",
  "CVE-2008-1009",
  "CVE-2008-1010",
  "CVE-2008-1011"
 );
 script_bugtraq_id(
  28326,
  28328,
  28330,
  28332,
  28335,
  28336,
  28337,
  28338,
  28342,
  28347,
  28356
 );
 script_osvdb_id(
  43359,
  43360,
  43361,
  43362,
  43363,
  43364,
  43365,
  43366,
  43367,
  43368
 );

 script_name(english:"Mac OS X : Apple Safari < 3.1");
 script_summary(english:"Check the Safari SourceVersion");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by several
issues.");
 script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote host is older
than version 3.1.

The remote version of this software contains several security
vulnerabilities that may allow an attacker to execute arbitrary code
or launch a cross-site scripting attack on the remote host.

To exploit these flaws, an attacker would need to lure a victim into
visiting a rogue website or opening a malicious HTML file.");
 script_set_attribute(attribute:"see_also", value:"http://docs.info.apple.com/article.html?artnum=307563");
 script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 3.1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(79);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/17");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/03/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/18");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

 script_family(english:"MacOS X Local Security Checks");

 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");
 exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");


# Get Safari version and save it in the KB for other plugins.
path = '/Applications/Safari.app';
plist = path + '/Contents/Info.plist';
cmd =
  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleGetInfoString | ' +
  'tail -n 1 | ' +
  'sed \'s/<string>\\(.*\\)<\\/string>.*/\\1/g\' | ' +
  'awk \'{print $1}\' | ' +
  'sed \'s/,//g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) audit(AUDIT_VER_FAIL, "Safari");

kb_base = "MacOSX/Safari";
set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Path", value:path);

version = chomp(version);
if (!ereg(pattern:"^[0-9]+[0-9.]+$", string:version)) exit(1, "The Safari version does not appear to be numeric ("+version+").");
set_kb_item(name:kb_base+"/Version", value:version);


# Mac OS X 10.4, 10.5.2
uname = get_kb_item_or_exit("Host/uname");
if (!egrep(pattern:"Darwin.* (8\.|9\.[012]\.)", string:uname))
  audit(AUDIT_HOST_NOT, "Mac OS X 10.4.x / 10.5 / 10.5.1 / 10.5.2");

# And now the actual check.
fixed_version = "3.1";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Safari", version);
