#TRUSTED 56e82a51cd56a54b61dd43eee53e4aa4b72e338e985a4a3fdf1582a9a5ccda5f4c83e2af8b3cc3ebf8c2a1ec966c57c0c49ab4ca5c46e034ddc562ab0b2bc1a58ce88485488d5f0b60337092fb44611a35c90b10235cb386ab56793efdd2fba4a907a2034ab6067576709fc9291c0a776dc68da9ecbc58ff0a0fff08ea055956b041eab0cae39a0267f5de7b1ad8f4e434b4fe78107540386051d961a902d62aa7ef0fe0f71c6875fbbe1e85b34570fdf1b1ec8e62a30dd13044dec1ea3be6937febf3afa556a84f78c7490eda9723b5b845db4e8c6d4e1c3bb153fb1744f5b97997764053d4598c8c5a1f8b67cbaa58d5cce96ca66e1d00a01f616285850a2ca1111523b8254c98063b54053c837590ec53ef4322be48076b26a852eab34104eecaef1f03c1029c116c93d784ff7a40464e5dce447993d64ac5fbc7d5ea17e6b184896f723bf3d0031a752135d9f155b6da094fe0aa70f30fe14c0a16bd3fd2e05cbe173468c837d08de18205bb30d3054775f0095e85ada40d5dae11fe2c6ace9116390b90efaf03fa255b77e0e7274c7f88aa756e37ea7c88b154556528b9d70517c3a7798439b2ab9421c574d9b7e71fd32fb6a7b018fae99eb4ef0b55c673fa84a998f0828e481a4c896e7a5a4b1c1d893d430c52bf00170aa67cf7399c44c2a655728a0791c1ac0926f9f2b614c12174d4ccb1983eee86650dca4ccd29
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70940);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/24");

  script_cve_id("CVE-2013-5558");
  script_bugtraq_id(63552);
  script_osvdb_id(99489);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj17238");
  script_xref(name:"IAVA", value:"2013-A-0211");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20131106-tvxca");

  script_name(english:"Cisco TelePresence VX Clinical Assistant WIL-A Module Reboot Admin Password Removal");
  script_summary(english:"Attempts to authenticate to the remote host with a blank password");

  script_set_attribute(attribute:"synopsis", value:"The remote system has an account with a blank password.");
  script_set_attribute(attribute:"description", value:
"Cisco TelePresence VX Clinical Assistant is affected by a password
reset vulnerability. The WIL-A module causes the administrative
password to be reset to a blank password every time the device is
rebooted.

This plugin attempts to authenticate to the device using the username
'admin' and a blank password over SSH. It does not attempt to obtain a
version number and does not fully validate that the remote host is a
Clinical Assistant device.");
  # http://threatpost.com/cisco-fixes-blank-admin-password-flaw-in-telepresence-product
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5ef8f99");
  script_set_attribute(attribute:"solution", value:
"Follow the manufacturer's instructions to upgrade to a firmware
version later than 1.20");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_vx_clinical_assistant");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_require_keys("Settings/ParanoidReport");
  script_dependencies("find_service1.nasl");
  script_require_ports("Services/ssh", 22);
  script_exclude_keys("global_settings/supplied_logins_only");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
port = kb_ssh_transport();

if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

_ssh_socket = open_sock_tcp(port);

if (!_ssh_socket) audit(AUDIT_SOCK_FAIL, port);

ret = ssh_login(login:"admin", password:"");
if (ret != 0) audit(AUDIT_RESP_BAD, port, "keyboard authentication with a blank password");

welcome = ssh_cmd(cmd:"", noexec:TRUE, nosh:TRUE, nosudo:TRUE, timeout:10);
ssh_close_connection();

if ('Welcome to \r\nCisco Codec Release ' >!< welcome)
  audit(AUDIT_NOT_DETECT, "Cisco TelePresence");

report = NULL;

if (report_verbosity > 0)
{
  report = '\nNessus was able to authenticate to the remote host' +
           '\nusing the username "admin" with a blank password.' +
           '\n';
}
security_hole(port:port, extra:report);
