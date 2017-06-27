#TRUSTED 510cb33d7e14ac63b9678cfd334068552cd9fa6553467099c025e8cb4fa9167c01544d470fb83b767e1e27de4f441c8e9a4029637e8fae15c7998303f56dd82fe16cf1b49f61ddaa545dbffa331539154db87eff90ce198b908ac391b94a7ca5921030e3d51e58da91e5b74acfdebf013b73b1691d9b30c390149de14e869041a6550df3661ad004d7e5b7aa25fb979a117651946d4fef259d8ab944be8adf17ac1c47b655b8342996e3a3bc67ca17354fb97c587903351eab7413bc9a03bc2187319a17a5b1d03f6e93040e195dc3818a60cdeaaab31492b2b04446619bf11a3bb5ba54af2c33c22085ef22d56d58cb4342d5db3cb4c4487b3dba8f2050ec71e4a20b46fedff2242d16dc74d7e36b05b19a0d438ae1bfa22632fc27559f6dfbc6b4c24b7c97e192af3c2faed34f43d9548f8f5b0a3568f1aaf291d542e6b209e3b6013f4afbe1dd66d2b31f76dc493653b2d94687aa2731cab6e5a231f751cb59e1d130d612e27877d7032d4d78b167d7923c67feaebcc3a7cac8ed7a8186075b0cd87f4bb6dbd5b2522f9fb687c94a580a52295821927f25b4b02305b1246ebe5a3235c1d73f3fd50d7e823d43d0d7ec942c32c732d97b8c7aa0d2750d9d43cb2a8480c524f80d0bd41658156cb34c2fa5754f77d71fced339fed31e4bf68e56db32edd572b672cf569a5720791e230492861350fdfab1b467780abc5c662e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80194);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-3412");
  script_bugtraq_id(67454);
  script_osvdb_id(106939);

  script_name(english:"Juniper Junos Space < 13.3R1.8 Arbitrary Command Execution (JSA10626)");
  script_summary(english:"Checks the version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote command execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos Space
version is prior to 13.3R1.8. It is, therefore, affected by a remote
command execution vulnerability that exists when the firewall is
disabled. This could allow a remote attacker to execute arbitrary
commands with root privileges.

Note that the firewall is enabled by default on Junos Space.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10626");
  script_set_attribute(attribute:"solution", value:"Upgrade to Junos Space 13.3R1.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_space");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Junos_Space/version", "Host/Junos_Space/release");

  exit(0);
}

include("audit.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("junos.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/Junos_Space/release");
if (isnull(release) || "Junos Space" >!< release) audit(AUDIT_OS_NOT, "Juniper Junos Space");

ver = get_kb_item_or_exit('Host/Junos_Space/version');
if(_junos_space_ver_compare(ver:ver, fix:'13.3R1.8') >= 0)
  exit(0, 'Junos Space ' + ver + ' is not affected.');

if(report_paranoia < 2)
{
  if ( islocalhost() )
  {
    if ( ! defined_func("pread") ) exit(1, "'pread()' is not defined.");
    info_t = INFO_LOCAL;
  }
  else
  {
    sock_g = ssh_open_connection();
    if (! sock_g) exit(1, "ssh_open_connection() failed.");
    info_t = INFO_SSH;
  }

  cmd = 'service iptables status';
  buf = info_send_cmd(cmd:cmd);

  ssh_close_connection();

  if ("Firewall is not running" >!< buf)
    exit(0, "The firewall is enabled on the remote host.");
}
security_report_v4(port:0, extra:get_report(ver:ver, fix:'13.3R1.8'), severity:SECURITY_HOLE);
