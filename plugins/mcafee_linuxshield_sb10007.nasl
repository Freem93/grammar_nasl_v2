#TRUSTED ace75032aecef839b284c89eb1cc566eb266bf57b8789b00153e21fcd81a52cbf3333c16a20fdde95616c55db50a846f84306707b5ac11defebab853a3c47f82d511fe251058ffc0f9cf9d4ac16eb49a819b9d8852f1bb69abaae2ddd37524eebefe1bc08bbf41ed916e9fd302f3bfed371d369cd419dd94d084ef99f5b3fc72a8ae086e08d82d4505cb5f0ddf9bb41d0695e64b1976fac326d44f3fa3dfa706f2e739213a58afe043279dc6563ed70ccbf8d18ec5ab22e9cb7a08da74a09f6435ad2ad0ba30f22da401b906bcfe47a1f292b156ea347b76c11fa172ff7c9e97b9aad78c462d1561df2db6b49c90c293115ea1ea142dc2c8c3fdaa9eedfd803612ec1744ec9d3859ab11c3c1cf9cf8df9c209fed784e2989227490f32b8827aa370bc0d2a2cf62f6ffdcc6a1fd2c55e5faa28601f012bb5f9dfa500796d80e86b9d04c05b0c9f6c8808fcf39940f70eaecc47594f43da4f528e6ef321d7b50aa1ff8e685fbe97ad24759088fd7e8356484d023aa509c78befb32915020d03a731078efd4d2050a5d732a201e49744a94647ca3464c35791db40b287cd07bec2ae4dc53035f235574b97f8b10c6d01c3697f29fb599c959624da523c4fa26fe07246de3fbaf417adf5d09e297468c0eb51e7ae2bf1c7f419cc7bcecbeebbc04a51c87f9af97dc2ec91e58a5131922dead35d1f332999cdd82f817150e9e7efd45
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70195);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/05/03");

  script_cve_id("CVE-2009-5116");
  script_bugtraq_id(38489);
  script_osvdb_id(62666);
  script_xref(name:"EDB-ID", value:"14818");

  script_name(english:"McAfee LinuxShield <= 1.5.1 nailsd Daemon Remote Privilege Escalation");
  script_summary(english:"Logs in with SSH and checks the version of McAfee LinuxShield");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee LinuxShield installed on the remote host is 1.5.1
or earlier.  As such, it potentially is affected by a privilege
escalation vulnerability because it does not properly authenticate
clients.  An attacker able to log into the remote host can leverage this
vulnerability to authenticate to the application's 'nailsd' daemon and
do configuration changes as well as execute tasks subject to the
privileges with which the 'nailsd' daemon operates.");
  script_set_attribute(attribute:"see_also", value:"http://sotiriu.de/adv/NSOADV-2010-004.txt");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2010/Mar/26");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LinuxShield 1.5.1 if necessary and install hotfix
HF550192");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:linuxshield:1.5.1");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

if ("Linux" >!< get_kb_item_or_exit("Host/uname")) audit(AUDIT_OS_NOT, "Linux");

hotfixable_ver = "1.5.1";
hotfix = "HF550192";
cat_config_cmd = "cat /opt/NAI/LinuxShield/etc/config.xml";
cat_hfversion_cmd = "cat /opt/NAI/LinuxShield/etc/HF-Version";

port = kb_ssh_transport();

ret = ssh_open_connection();
if (ret == 0) audit(AUDIT_SVC_FAIL, "SSH", port);

cat_config_output = ssh_cmd(cmd:cat_config_cmd, nosh:TRUE, nosudo:FALSE);
if (
  isnull(cat_config_output) ||
  !eregmatch(pattern:"<InstalledPath>__NAILS_INSTALL__</InstalledPath>", string:cat_config_output)
) audit(AUDIT_NOT_INST, "McAfee LinuxShield");

matches = eregmatch(pattern:"<Version>([0-9]+\.[0-9]+\.[0-9]+)</Version>", string:cat_config_output);
if (isnull(matches)) audit(AUDIT_VER_FAIL, "McAfee LinuxShield");

ver = matches[1];

# We treat a missing HF-Version file and an empty one the same way
cat_hfversion_output = ssh_cmd(cmd:cat_hfversion_cmd, nosh:TRUE, nosudo:FALSE);
if (isnull(cat_hfversion_output)) cat_hfversion_output = "";

# If this is 1.5.1, has the hotfix been applied?
if (ver == hotfixable_ver && egrep(pattern:"^" + hotfix + "$", string:cat_hfversion_output)) audit(AUDIT_PATCH_INSTALLED, hotfix);

# If this is not 1.5.1, is it > 1.5.1?
if (ver_compare(ver:ver, fix:hotfixable_ver, strict:FALSE) == 1)  audit(AUDIT_INST_VER_NOT_VULN, "McAfee LinuxShield", ver);

if (report_verbosity > 0)
{
  vuln_report += '\n  Version       : ' + ver +
                 '\n  Fixed version : ' + hotfixable_ver + " with " + hotfix + " applied" +
                 '\n';
  security_warning(port:0, extra:vuln_report);
}
else security_warning(0);
