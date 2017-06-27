#TRUSTED 1a04d8ad109e0fa07b7ec511f72712e4009f2926e0c97cff4fdc95f18c2bbf4acaf42c3d8278b8dc98ee55937f4f412818d648dcbc1f040525a2df43e44feecc8b3cba493183813b1c30f5c8b3f45327980868438d464b76822f5e5303366e2023058c8a377ac1eb34733ac8820897fca11c4fa808c5fb08a3cf27c73f8f2a618f94e5180092ff12a5d5f4149f3083ceb40ffa1090836d86a79cd5fddf24e987123e9c44a028d81dac94b70e219e7ad7a82a75280555f711aa2a4261e937db1fd4f25f0660805b5c9e00cf8515130841e8a8dd7c2b155a2ffef722ea1d4beb218a7302df1794516d79796d3d60a2c95483802750f0a0fe16c0df9e3e5569fa36f739253d6c48816feb978a30f91854a9ef07c823f25f25724d64179121800840bef33f7ed0ddb4bfdbd82899e34388c011c31483f6b706aebc3c425a3cc16df71bcfdb952c8371c4b866e83c0279426e3e07e416fb22456d7a9414c79e13ab142e7aa344f7e1d5aa028f3f590fdc2d72cc623e3c646a1860532b6404f0fa94e2dfbced34200d600e4dd46d12707c7535b571f134d6eb02e37ae325fe067ff30d23d05286cdd3d0c4d6e110c2a3270446e8b9982ce2531431e9b599de7ac00f6b5f49e019ad92b61d891312a8c51569dc14cfadee30d1fa424ff9db810fe918af7ec0a56d9f8ce5eb713a7fbcda2967bdc9d51e0cbeb10676c6f6942309cd7fac
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86906);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/05/03");

  script_osvdb_id(130100);

  script_name(english:"Palo Alto Networks PAN-OS API Key Persistence Security Bypass (PAN-SA-2015-0006)");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an authentication security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Palo Alto Networks PAN-OS running on the remote host is a version
prior to 6.1.7 or 7.x prior to 7.0.2. It is, therefore, affected by a
security bypass vulnerability due to a failure to invalidate the local
administrator API keys after a password change has been performed, the
old keys being valid up until the time the device is rebooted. A
remote attacker can exploit this to gain access to the management
interface.");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/33");
  # https://www.paloaltonetworks.com/documentation/70/pan-os/pan-os-release-notes/pan-os-7-0-2-addressed-issues.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?83755f2d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 6.1.7 / 7.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");

app_name = "Palo Alto Networks PAN-OS";
version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Version");
full_version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Full_Version");
fix = NULL;

# Ensure sufficient granularity.
if (
  version =~ "^6(\.1)?$" ||
  version =~ "^7(\.0)?$"
) audit(AUDIT_VER_NOT_GRANULAR, app_name, full_version);

if (version =~ "^7\.0\.")
{
  fix = "7.0.2";
}
else if (
  version =~ "^[0-5]($|[^0-9])" ||
  version =~ "^6\.0($|[^0-9])" ||
  version =~ "^6\.1\."
)
{
  fix = "6.1.7";
}
else
  audit(AUDIT_NOT_INST, app_name + " 0.x-6.1.x / 7.0.x");

# Compare version to fix and report as needed.
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + full_version +
      '\n  Fixed versions    : ' + fix +
      '\n';
    security_warning(extra:report, port:0);
  }
  else security_warning(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
