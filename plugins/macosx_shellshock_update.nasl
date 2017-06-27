#TRUSTED 12eb8261df661821bce2458fe52a2bbbab0e1a6476840f31c642d7c8709a0cb323da64e2239f3fecb4db79294e67d4e4c2edf01bc34cc097dfc502993b4857905fecac94cb88410e7aee8e8ac0d3b76e426001899dd868f6f092c8cc42f529f597dd2f8f0a28ca83e3ec1c194c29733c190515bad3b62a6db47414064afafc12038f35064d7a0b8d386f58216c29c6ee75439d0d59094cb07d22af0c54e2eb6547038b2f1c772133465a1c2989496609d7f7a3d68cacad0b800bd9742071b72efd01d16e5c09af7406843c1584b0162162d20461602873a1f0396b7bececdc7e5ad1fc55eb1b467caaa01178e6948d1b9b85366d62e63067cf20cc2faf1d52ee9e8c8a07b3cbebcf2b85a93945fea93f898c2f252c4ea8cdb4c2e3f3924009ebbcda3ea950611a855522d3148d008d417c321de1dbe38e623fcf89ca89dede873389d3d4e76cf6913249e62d4593fe304c9df8afb62cffe2d6e253b968300aa35968417908fdeee7eceab572ab33ea8f77eaca3bd41fb2e5444fb537eebc8b30e408efc087e6be8a940e37488fb92a7ec45283c21b50ddf47d3f3e4dd97bb537d6ba7d4a5e4708e01e2cc49870fc9dc15029acd72026877196fddc74c8ae0c3e66035d6b4994e050b39ce77ff22cb7ac48a9d35c9ea5508d0deedc481a4346194fc3a151e8c7920a7ba0e8e88af35cfca9cd213c5e385f8a9af83c709b452f72
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77971);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/25");

  script_cve_id("CVE-2014-6271", "CVE-2014-7169");
  script_bugtraq_id(70103);
  script_osvdb_id(112004);
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");

  script_name(english:"GNU Bash Local Environment Variable Handling Command Injection (Mac OS X) (Shellshock)");
  script_summary(english:"Checks the version of Bash.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is is affected by a remote code execution
vulnerability, commonly referred to as Shellshock.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Bash prior to
3.2.53(1)-release installed. It is, therefore, affected by a command
injection vulnerability via environment variable manipulation.
Depending on the configuration of the system, an attacker could
remotely execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6495");
  # https://lists.apple.com/archives/security-announce/2014/Sep/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5039c7b");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/DL1767");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/DL1768");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/DL1769");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"solution", value:"Apply the vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Pure-FTPd External Authentication Bash Environment Variable Code Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:bash");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

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
if (!ereg(pattern:"Mac OS X 10\.[7-9]([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.9 / 10.8 / 10.7");

ver_sh = NULL;
ver_bash = NULL;

pat = "version ([0-9.]+\([0-9]+\))(\-[a-z]+)?";

cmd = "bash --version";
result = exec_cmd(cmd:cmd);
item = eregmatch(pattern:pat, string:result);
if (!isnull(item)) ver_bash_disp = item[1];

cmd = "sh --version";
result = exec_cmd(cmd:cmd);
item = eregmatch(pattern:pat, string:result);
if (!isnull(item)) ver_sh_disp = item[1];

if (ver_sh_disp)
{
  ver_sh = ereg_replace(string:ver_sh_disp, pattern:"\(", replace:".");
  ver_sh1 = ereg_replace(string:ver_sh, pattern:"\)", replace:"");
}
else ver_sh1 = NULL;
if (ver_bash_disp)
{
  ver_bash = ereg_replace(string:ver_bash_disp, pattern:"\(", replace:".");
  ver_bash1 = ereg_replace(string:ver_bash, pattern:"\)", replace:"");
}
else ver_bash1 = NULL;

fix_disp = '3.2.53(1)';
fix = '3.2.53.1';

if (
   (!isnull(ver_sh1) && ver_compare(ver:ver_sh1, fix:fix, strict:FALSE) == -1) ||
   (!isnull(ver_bash1) && ver_compare(ver:ver_bash1, fix:fix, strict:FALSE) == -1)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + ver_bash_disp  +
      '\n  Fixed version     : ' + fix_disp +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Bash', ver_bash_disp);
