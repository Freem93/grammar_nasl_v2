#TRUSTED 2fff6649defbe13e401aa9c9d0d5219820c748e81a5f3e1acac893b9e15b07bcb2ef4268d5b2ddbbffb894c1d88e17f692dfb9486e8d993b8e309854d0a278d9ed89340a07014670d3ee9f03aaae5c89a58cf47dffd35937a56517794f49effa6d3b9661a14ecc6a11f0af34641ed67a535c051eaf4e49f1cb819c1b97d3d61bd02a4adcb283d97fbc5c7276cf549c368bfb80904ad4e1b935dcf42686bc3caec14d7e6938e82e7333b8320b1c6461890f5746ffc276b8eb6a7b7d1b1a5a7ca0af679f22f852e016d3b65db36d12496f67c9a07c09fbe5f241723699463df0f00208025074bfd03b181c252ccee0f7164b644fe0d6e881f22a0fde6b3789cf18b13b5b7d6158d118da157139a494a0ad0969198359ce11e104e68aa6bb4136cecfb3d7965bb59a82f7b5e22b598038ace58cdfe41ea6979ad16cadb85ce0d0e41cbd43a5be11bf07133303629b2a2177f4d270865e05d2ceee2326270997fd88a438076bacbde4d5b5538fc3f5d6cedb8c5bbd93a1d204b369707593d326d5f8a155630d995f9c36e3349f94d3b56f007c1f203d48a6458330569daf3d625a0765c8c3ecfbdcfaef653367affeb43e76884b7b5c6a69998d24a8d84c995b5419b8f6077fd50358cb032cf6bfa188ff113ef6b5e684b2d9f10331b32caf78194e35fa1e1d74d0bcecf1f57f7097cb4674b899819d8df46efb420768a60a514350
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70731);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/10/16");

  script_cve_id("CVE-2013-3834");
  script_bugtraq_id(63138);
  script_osvdb_id(98519);

  script_name(english:"Oracle Secure Global Desktop ttaauxserv Remote Denial of Service (credentialed check)");
  script_summary(english:"Checks if patch is installed");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by a denial
of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a version of Oracle Secure Global Desktop
installed that has an unspecified denial of service vulnerability in
the ttaauxserv binary that may be triggered by a remote attacker."
  );
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac29c174");
  script_set_attribute(
    attribute:"solution",
    value:
"Install the patched binary per the instructions in the vendor's
advisory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:virtualization_secure_global_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("oracle_secure_global_desktop_installed.nbin");
  script_require_keys("Host/Oracle_Secure_Global_Desktop/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

version = get_kb_item_or_exit("Host/Oracle_Secure_Global_Desktop/Version");
if (version != "5.00.907") audit(AUDIT_INST_VER_NOT_VULN, version);

# this check is for Oracle Secure Global Desktop packages built for Linux platform
uname = get_kb_item_or_exit("Host/uname");
if ("Linux" >!< uname) audit(AUDIT_OS_NOT, "Linux");

if (islocalhost())
{
  if (!defined_func("pread")) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) exit(1, "Failed to open an SSH connection.");
}

cmd = "dd if=/opt/tarantella/bin/bin/ttaauxserv bs=10000 count=359 | md5sum";
cmd1 = "dd if=/opt/tarantella/bin/bin/ttaauxserv bs=10000 skip=360 | md5sum";

res = info_send_cmd(cmd:cmd);
if (strlen(res) == 0)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(0, 'No results returned from "' + cmd + '" command ran on remote host.');
}

if (res !~ "^[0-9a-f]{32}([ ]|$)")
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(0, 'Unexpected output from "' + cmd + '"');
}

res1 = info_send_cmd(cmd:cmd1);
if (info_t == INFO_SSH) ssh_close_connection();

if (strlen(res1) == 0) exit(0, 'No results returned from "' + cmd1 + '" command ran on remote host.');
if (res1 !~ "^[0-9a-f]{32}([ ]|$)") exit(0, 'Unexpected output from "' + cmd1 + '"');

if (
  "e8490e71847949c9cd161db9f9eece95" >!< res ||
   "bfcc1282a99455ffeab15a348a1cf3f8" >!< res1
) audit(AUDIT_INST_VER_NOT_VULN, "Oracle Secure Global Desktop");

if (report_verbosity > 0)
{
  report = '\n  Version          : ' + version +
           '\n  Unpatched binary : /opt/tarantella/bin/bin/ttaauxserv\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);
