#TRUSTED 5d95fe490fdbc0a9b83e648f1927b1d9fdfd4d7c898622acf8712e46400843e17cec99c6ce7e3e5946e0f0ac0a16a46bca17b3eda09bca23e65e87bdbaaded41c6357f85883fe80babb27c691c209c1a0c8dd6092e7ca3147bb545ce25d4b3b51176935a795be6cea7a98d9f0fa501cb3650cbab5d4c6b7e8237cf36776a60796d16149afd236b4a7bfd90732a4fe01a57facb5eda759ed55c01580d28dea8db93c95e001de8148ae84573b5b91aa1082c4fa67f457c922ac3ccd6f9c814f7f3566b805e38b139626341b19c6d5bb2b0d05ea5038d5163ffc6b5f695d958ecdffc09bb4ce09ec6d0d655bf07dc3280a1c2e8d60c06a39e2375714f696a6a9bcc20f454f21f8190bece816a9aa10621cca367b514a1769c82d25b5b99005f296bac21c7c140ada613694261c54a5d93a79ebb3d243919fd96ff55cc19933fbb2a33c14dea7d56835b3a3836262e2d6bc95dd33c10291cbc40866b8000bda23cc406cb8436aa5d9f4cf282161e07e09fcfc4452641b282e69627c824396438212ea9e4149982a5cb688f666b00718714a1480664b2a777a74ee3288d1df4b516e037a11cd6f76fb088bbf488d5a5706d14c9fcfc014e78ab7ec0b153a41d6c523ee3af9d4545b98aaa659e612d3747cd83f27b37755084530f7ab11c2ed99637193c83e2f68f43ebb9ae65f6244740fc0f56bbfa947b79e653f5c4ef252105e233
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70546);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/10/17");

  script_cve_id(
    "CVE-2013-3762",
    "CVE-2013-5766",
    "CVE-2013-5827",
    "CVE-2013-5828"
  );
  script_bugtraq_id(63056, 63064, 63068, 63071);
  script_osvdb_id(98470, 98471, 98472, 98473);

  script_name(english:"Oracle Database Management Plug-In October 2013 Unix (credentialed check)");
  script_summary(english:"Checks for patch ID");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a database management application installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Database Management Plug-In is missing the October
2013 Critical Patch Update (CPU) and is, therefore, potentially affected
by security issues in the Enterprise Manager Base Platform.");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac29c174");
  script_set_attribute(attribute:"solution", value:"Apply the October 2013 CPU.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager_plugin_for_database_control");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

# Only the following OSes are currently supported
unsupported = 1;
if (
  get_kb_item("Host/CentOS/release") ||
  get_kb_item("Host/Debian/release") ||
  get_kb_item("Host/FreeBSD/release") ||
  get_kb_item("Host/Gentoo/release") ||
  get_kb_item("Host/HP-UX/version") ||
  get_kb_item("Host/Mandrake/release") ||
  get_kb_item("Host/RedHat/release") ||
  get_kb_item("Host/Slackware/release") ||
  get_kb_item("Host/Solaris/Version") ||
  get_kb_item("Host/SuSE/release") ||
  get_kb_item("Host/Ubuntu/release") ||
  get_kb_item("Host/AIX/version")
) unsupported = 0;

if (unsupported) exit(0, "Oracle Database Management Plug-In checks are not supported on the remote OS at this time.");

# We may support other protocols here
if ( islocalhost() )
{
  if (!defined_func("pread")) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

# Find the inventory.xml file and read it in
# Parse the results to get the paths and version of the DB plugins
info = "";
cmd =
  'cat /etc/oraInst.loc | ' +
  'grep -h "inventory_loc=" | ' +
  'sed \'s/inventory_loc=\\(.*\\)/\\1\\/ContentsXML\\/inventory.xml/g\' | xargs cat';

paths = make_array();
buf = info_send_cmd(cmd:cmd);
if (buf)
{
  buf = chomp(buf);
  if ('HOME NAME="oms12c' >< buf)
  {
    chunk = strstr(buf, '<HOME NAME="oms12c') - '<HOME NAME="oms12c';
    chunk = strstr(chunk, '<REFHOMELIST>') - '<REFHOMELIST>';
    chunk = chunk - strstr(chunk, '</REFHOMELIST>');
    chunk = chomp(chunk);

    foreach item (split(chunk))
    {
      path = '';
      # If the item is a DB 12.1.0.3 or 12.1.0.4 plugin, save the path
      if ('oracle.sysman.db.oms.plugin_' >< item && ('12.1.0.2' >< item || '12.1.0.3' >< item || '12.1.0.4' >< item))
      {
        path = ereg_replace(pattern:'^\\s+<REFHOME LOC="([^"]+)".*', string:item, replace:"\1");
        version = strstr(path, 'plugin_') - 'plugin_';
        paths[version] = path;
      }
    }
  }
}

if (max_index(keys(paths)) == 0) exit(0, "No affected Oracle Database Management Plug-Ins were detected on the remote host.");

# Loop over the DB Management Plug-In paths
info = '';
foreach version (keys(paths))
{
  if ('12.1.0.2' >< version) patchid = '15985383';
  else if ('12.1.0.3' >< version) patchid = '17171101';
  else if ('12.1.0.4' >< version) patchid = '17366505';

  path = paths[version];
  buf = info_send_cmd(cmd:"cat " + path + "/.patch_storage/interim_inventory.txt");

  if (!buf)
    info += '  ' + version + '\n';
  else
  {
    # Parse the file to see what patches have been installed
    buf = chomp(buf);
    chunk = strstr(buf, '# apply: the patch to be applied.') - '# apply: the patch to be applied.';
    chunk = chunk - strstr(chunk, '# apply: list of patches to be auto-rolled back.');
    chunk = chomp(substr(chunk, 1));

    if (patchid >!< chunk)
      info += '  ' + version + '\n';
  }
}

if (info)
{
  if (report_verbosity > 0)
  {
    report +=
      '\nThe following affected Oracle Database Managment Plug-Ins were detected' +
      '\non the remote host :' +
      '\n' +
      info;
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
