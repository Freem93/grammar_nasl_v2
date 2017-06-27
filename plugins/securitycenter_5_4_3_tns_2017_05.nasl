#TRUSTED 2367f370d73f80939ca8f31a410c9b1280db1361a4bc124502ed8af4cf7aab4cb5a8164e65f73c337a6e3fb7ac2da1dfc8049f1f6065550dcfe6fe3f97a565b997220007c8d26b1990a970687dccdcff18498c75a80798b0811dc45f395ba600ced833f4afba90a627e18155fb48f528f1dc832edeaa8bb641ab3fcb585f17881d6d5cdacc95c83e53eeea11bde8b420c48261b746c1a962883f9903241d6861cf5387c415ad8e2322ab17459b2a94fb025704b79fb7445d6ff257267e053bee3024835b7870a5071396660cadc54690dcd77bb6042ac5aa8c4f406c7c95564a8df24745fbe409dc416ebe9d701aa80ac8e559351048fca0fcc55ed57224aa8a66d3e6889d97c734024a235b333b4870c8e395d7c405e17212c6ab1b6369af7a070264f735b825d0b1d956b2c5eea75855221665c40fe0dbb6a4a9fe1a268bf3780df0e48a5f2e18697c14985cc87d79ccbdc3a5a737f36815e1eb52d96fe2b5e3fdea7449ca8f68eac6aa146b20cb7a6cfe02db56ffdb2430f8ffb4d0b577d4aa2a1af34e56e343b89cab846465a74914c0eb2a940cbd608d868770f1284a03cf17651b1425e78642d5c00fdd119116afbb68681a1ba3185cdf7f3ff9bc0948b075c0ff843327a640248da3e7c91b6f08d555c163ddd938703b1b4441a9575520d767d4fe2d5d2699b77462720a3413782cbcd577bd3e75ea265917dbedce88
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97575);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/07");

  script_osvdb_id(152286);

  script_name(english:"Tenable SecurityCenter 5.4.x <= 5.4.3 PHP Object Deserialization Remote File Deletion (TNS-2017-05)");
  script_summary(english:"Checks the SecurityCenter version.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a PHP
object deserialization vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Tenable SecurityCenter
on the remote host is affected by a PHP object deserialization
vulnerability in the PluginParser.php script. An authenticated, remote
attacker can exploit this, by uploading a specially crafted PHP
object, to delete arbitrary files on the remote host.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/security/tns-2017-05");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_keys("Host/SecurityCenter/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item_or_exit("Host/SecurityCenter/Version");
vuln = FALSE;

# Affects versions 5.4.0 - 5.4.3
if (version =~ "^5\.4\.[0-3]$")
{
  # Establish running of local commands
  if ( islocalhost() )
  {
    if ( ! defined_func("pread") ) audit(AUDIT_NOT_DETECT, "pread");
    info_t = INFO_LOCAL;
  }
  else
  {
    sock_g = ssh_open_connection();
    if (! sock_g) audit(AUDIT_HOST_NOT, "able to connect via the provided SSH credentials.");
    info_t = INFO_SSH;
  }

  # Check version
  res = info_send_cmd(cmd:"cat /opt/sc/src/lib/PluginParser.php");
  if (! res) exit(1, "The command 'cat /opt/sc/src/lib/PluginParser.php' failed.");

  if ('$errorText = "Possible exploit attempt intercepted' >!< res)
  {
    vuln = TRUE;
    fix = "Apply the patch referenced in the TNS-2017-05 advisory.";
  }
}

if (vuln)
{
  report =
    '\n  Installed version  : ' + version +
    '\n  Fixed version      : ' + fix + '\n';
  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'SecurityCenter', version);
